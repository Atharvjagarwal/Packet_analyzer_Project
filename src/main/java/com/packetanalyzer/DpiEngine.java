package com.packetanalyzer;

import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

public final class DpiEngine {
    public static final class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public int queueSize = 10_000;
        public int maxConnectionsPerProcessor = 100_000;
        public String rulesFile = "";
        public boolean verbose;

        private void validate() {
            if (numLoadBalancers < 1 || fpsPerLb < 1 || queueSize < 1 || maxConnectionsPerProcessor < 1) {
                throw new IllegalArgumentException("Thread counts, queue size, and connection limit must be positive");
            }
            Math.multiplyExact(numLoadBalancers, fpsPerLb);
        }
    }

    public static final class BlockingRules extends RuleManager {
        public void blockIp(String ip) {
            blockIP(ip);
        }

        public void unblockIp(String ip) {
            unblockIP(ip);
        }

        public boolean isBlocked(long srcIp, DpiTypes.AppType appType, String domain) {
            return super.isBlocked(srcIp, appType, domain);
        }
    }

    public record EngineStats(long totalPackets, long totalBytes, long forwardedPackets,
            long droppedPackets, long tcpPackets, long udpPackets, long otherPackets,
            int activeConnections, Map<DpiTypes.AppType, Long> classifications) {
    }

    private final Config config;
    private final RuleManager rules;
    private final AtomicBoolean running = new AtomicBoolean();
    private final AtomicBoolean stopRequested = new AtomicBoolean();
    private final AtomicReference<Thread> activeThread = new AtomicReference<>();
    private final AtomicLong totalPackets = new AtomicLong();
    private final AtomicLong totalBytes = new AtomicLong();
    private final AtomicLong forwardedPackets = new AtomicLong();
    private final AtomicLong droppedPackets = new AtomicLong();
    private final AtomicLong tcpPackets = new AtomicLong();
    private final AtomicLong udpPackets = new AtomicLong();
    private final AtomicLong otherPackets = new AtomicLong();
    private final Map<DpiTypes.AppType, LongAdder> appStats = new ConcurrentHashMap<>();
    private volatile GlobalConnectionTable globalConnectionTable = new GlobalConnectionTable();
    private volatile List<ConnectionTracker> trackers = List.of();
    private volatile List<Worker> lastWorkers = List.of();
    private volatile List<LoadBalancer> lastLoadBalancers = List.of();
    private volatile List<ThreadSafeQueue<PacketJob>> activePacketQueues = List.of();
    private volatile List<ResultQueue> activeResultQueues = List.of();
    private volatile IOException processingError;
    private volatile boolean initialized;

    public DpiEngine() {
        this(new Config(), new RuleManager());
    }

    public DpiEngine(Config config) {
        this(config, new RuleManager());
    }

    public DpiEngine(Config config, RuleManager rules) {
        this.config = config;
        this.rules = rules;
        config.validate();
    }

    public boolean initialize() {
        config.validate();
        if (!config.rulesFile.isBlank()) {
            try {
                if (!rules.loadRules(config.rulesFile)) {
                    return false;
                }
            } catch (IOException exception) {
                processingError = exception;
                return false;
            }
        }
        initialized = true;
        return true;
    }

    public RuleManager getRuleManager() {
        return rules;
    }

    public boolean isRunning() {
        return running.get();
    }

    public synchronized void processFile(String inputFile, String outputFile) throws IOException {
        if (!running.compareAndSet(false, true)) {
            throw new IllegalStateException("DPI engine is already processing a file");
        }
        stopRequested.set(false);
        resetStats();
        processingError = null;
        try {
            runPipeline(inputFile, outputFile);
        } finally {
            running.set(false);
            activeThread.set(null);
        }
        if (processingError != null) {
            throw processingError;
        }
    }

    public synchronized void start(String inputFile, String outputFile) {
        if (!running.compareAndSet(false, true)) {
            throw new IllegalStateException("DPI engine is already running");
        }
        stopRequested.set(false);
        resetStats();
        processingError = null;
        Thread thread = new Thread(() -> {
            try {
                runPipeline(inputFile, outputFile);
            } catch (IOException exception) {
                processingError = exception;
            } catch (RuntimeException exception) {
                processingError = new IOException("DPI processing failed", exception);
            } finally {
                running.set(false);
                activeThread.set(null);
            }
        }, "dpi-engine-coordinator");
        thread.setDaemon(false);
        activeThread.set(thread);
        thread.start();
    }

    public void stop() {
        stopRequested.set(true);
    }

    public void waitForCompletion() throws IOException, InterruptedException {
        Thread thread = activeThread.get();
        if (thread != null) {
            thread.join();
        }
        if (processingError != null) {
            throw processingError;
        }
    }

    public CompletableFuture<Void> processFileAsync(String inputFile, String outputFile) {
        return CompletableFuture.runAsync(() -> {
            try {
                processFile(inputFile, outputFile);
            } catch (IOException exception) {
                throw new java.util.concurrent.CompletionException(exception);
            }
        });
    }

    public EngineStats getStats() {
        Map<DpiTypes.AppType, Long> classifications = new EnumMap<>(DpiTypes.AppType.class);
        appStats.forEach((app, count) -> classifications.put(app, count.sum()));
        int active = globalConnectionTable.getStats().activeConnections();
        return new EngineStats(totalPackets.get(), totalBytes.get(), forwardedPackets.get(),
                droppedPackets.get(), tcpPackets.get(), udpPackets.get(), otherPackets.get(),
                active, Map.copyOf(classifications));
    }

    public String generateReport() {
        EngineStats stats = getStats();
        RuleManager.RuleStats ruleStats = rules.getStats();
        StringBuilder report = new StringBuilder();
        report.append("DPI Processing Report\n")
                .append("=====================\n")
                .append("Packets processed: ").append(stats.totalPackets()).append('\n')
                .append("Bytes processed: ").append(stats.totalBytes()).append('\n')
                .append("Packets forwarded: ").append(stats.forwardedPackets()).append('\n')
                .append("Packets dropped: ").append(stats.droppedPackets()).append('\n')
                .append("TCP packets: ").append(stats.tcpPackets()).append('\n')
                .append("UDP packets: ").append(stats.udpPackets()).append('\n')
                .append("Other packets: ").append(stats.otherPackets()).append('\n')
                .append("Active connections: ").append(stats.activeConnections()).append('\n')
                .append("Rules: ").append(ruleStats.blockedIps()).append(" IP, ")
                .append(ruleStats.blockedPorts()).append(" port, ")
                .append(ruleStats.blockedApps()).append(" app, ")
                .append(ruleStats.blockedDomains()).append(" domain\n")
                .append("Load balancers\n");
        lastLoadBalancers.forEach(lb -> report.append("  LB ").append(lb.id)
                .append(": received ").append(lb.packetsReceived.sum())
                .append(", dispatched ").append(lb.packetsDispatched.sum())
                .append(", per-FP ").append(java.util.Arrays.toString(
                        java.util.Arrays.stream(lb.perWorkerCounts)
                                .mapToLong(LongAdder::sum).toArray())).append('\n'));
        report.append("Fast-path processors\n");
        lastWorkers.forEach(worker -> report.append("  FP ").append(worker.id)
                .append(": processed ").append(worker.packetsProcessed.sum())
                .append(", forwarded ").append(worker.packetsForwarded.sum())
                .append(", dropped ").append(worker.packetsDropped.sum())
                .append(", SNI extracted ").append(worker.sniExtractions.sum())
                .append(", classifications ").append(worker.classificationHits.sum()).append('\n'));
        return report.toString();
    }

    public String generateClassificationReport() {
        StringBuilder report = new StringBuilder("Application Classification Report\n");
        getStats().classifications().entrySet().stream()
                .sorted(Map.Entry.<DpiTypes.AppType, Long>comparingByValue().reversed()
                        .thenComparing(Map.Entry.comparingByKey()))
                .forEach(entry -> report.append("  ")
                        .append(DpiTypes.appTypeToString(entry.getKey()))
                        .append(": ").append(entry.getValue()).append(" packets\n"));
        report.append('\n').append(globalConnectionTable.generateReport());
        return report.toString();
    }

    public void printStatus() {
        System.out.println("DPI engine " + (isRunning() ? "running" : "stopped"));
        System.out.print(generateReport());
    }

    public boolean saveRules(String filename) throws IOException {
        return rules.saveRules(filename);
    }

    public boolean loadRules(String filename) throws IOException {
        return rules.loadRules(filename);
    }

    public void blockIP(String ip) {
        rules.blockIP(ip);
    }

    public void blockIP(long ip) {
        rules.blockIP(ip);
    }

    public void unblockIP(String ip) {
        rules.unblockIP(ip);
    }

    public void unblockIP(long ip) {
        rules.unblockIP(ip);
    }

    public void blockApp(DpiTypes.AppType app) {
        rules.blockApp(app);
    }

    public void blockApp(String app) {
        rules.blockApp(app);
    }

    public void unblockApp(DpiTypes.AppType app) {
        rules.unblockApp(app);
    }

    public void unblockApp(String app) {
        rules.unblockApp(app);
    }

    public void blockDomain(String domain) {
        rules.blockDomain(domain);
    }

    public void unblockDomain(String domain) {
        rules.unblockDomain(domain);
    }

    public void blockPort(int port) {
        rules.blockPort(port);
    }

    public void unblockPort(int port) {
        rules.unblockPort(port);
    }

    public static void main(String[] args) throws Exception {
        if (List.of(args).contains("--help") || List.of(args).contains("-h")) {
            printUsage();
            return;
        }
        if (args.length < 2) {
            printUsage();
            System.exit(2);
        }
        String inputFile = args[0];
        String outputFile = args[1];
        Config config = new Config();
        RuleManager rules = new RuleManager();
        String saveRulesFile = null;
        String reportFile = null;
        boolean printClassification = false;

        for (int i = 2; i < args.length; i++) {
            String option = args[i];
            switch (option) {
                case "--block-ip" -> rules.blockIP(requireValue(args, ++i, option));
                case "--unblock-ip" -> rules.unblockIP(requireValue(args, ++i, option));
                case "--block-app" -> rules.blockApp(requireValue(args, ++i, option));
                case "--unblock-app" -> rules.unblockApp(requireValue(args, ++i, option));
                case "--block-domain" -> rules.blockDomain(requireValue(args, ++i, option));
                case "--unblock-domain" -> rules.unblockDomain(requireValue(args, ++i, option));
                case "--block-port" -> rules.blockPort(parseInt(requireValue(args, ++i, option), option));
                case "--unblock-port" -> rules.unblockPort(parseInt(requireValue(args, ++i, option), option));
                case "--rules", "--load-rules" -> {
                    String path = requireValue(args, ++i, option);
                    if (!rules.loadRules(path)) {
                        throw new IOException("Rules file does not exist: " + path);
                    }
                }
                case "--save-rules" -> saveRulesFile = requireValue(args, ++i, option);
                case "--report-file" -> reportFile = requireValue(args, ++i, option);
                case "--lbs" -> config.numLoadBalancers = parseInt(requireValue(args, ++i, option), option);
                case "--fps" -> config.fpsPerLb = parseInt(requireValue(args, ++i, option), option);
                case "--queue-size" -> config.queueSize = parseInt(requireValue(args, ++i, option), option);
                case "--max-connections" -> config.maxConnectionsPerProcessor =
                        parseInt(requireValue(args, ++i, option), option);
                case "--verbose" -> config.verbose = true;
                case "--report" -> printClassification = true;
                default -> throw new IllegalArgumentException("Unknown option: " + option);
            }
        }
        DpiEngine engine = new DpiEngine(config, rules);
        engine.processFile(inputFile, outputFile);
        System.out.print(engine.generateReport());
        if (printClassification) {
            System.out.print(engine.generateClassificationReport());
        }
        if (reportFile != null) {
            Files.writeString(Path.of(reportFile),
                    engine.generateReport() + "\n" + engine.generateClassificationReport(),
                    StandardCharsets.UTF_8);
        }
        if (saveRulesFile != null && !engine.saveRules(saveRulesFile)) {
            throw new IOException("Could not save rules to " + saveRulesFile);
        }
    }

    private void runPipeline(String inputFile, String outputFile) throws IOException {
        config.validate();
        if (!initialized && !initialize()) {
            throw processingError != null ? processingError
                    : new IOException("Could not initialize DPI engine or load configured rules");
        }
        if (Path.of(inputFile).toAbsolutePath().normalize()
                .equals(Path.of(outputFile).toAbsolutePath().normalize())) {
            throw new IOException("Input and output PCAP paths must be different");
        }
        int workerCount = config.numLoadBalancers * config.fpsPerLb;
        List<Worker> workers = new ArrayList<>(workerCount);
        GlobalConnectionTable connectionTable = new GlobalConnectionTable();
        for (int workerId = 0; workerId < workerCount; workerId++) {
            ConnectionTracker tracker = new ConnectionTracker(workerId, config.maxConnectionsPerProcessor);
            connectionTable.registerTracker(tracker);
            workers.add(new Worker(workerId, tracker, config.queueSize));
        }
        globalConnectionTable = connectionTable;
        trackers = workers.stream().map(worker -> worker.tracker).toList();
        lastWorkers = List.copyOf(workers);

        List<LoadBalancer> loadBalancers = new ArrayList<>(config.numLoadBalancers);
        for (int lbId = 0; lbId < config.numLoadBalancers; lbId++) {
            int start = lbId * config.fpsPerLb;
            loadBalancers.add(new LoadBalancer(lbId, workers.subList(start, start + config.fpsPerLb),
                    config.queueSize));
        }
        lastLoadBalancers = List.copyOf(loadBalancers);
        List<ThreadSafeQueue<PacketJob>> packetQueues = new ArrayList<>();
        loadBalancers.forEach(lb -> packetQueues.add(lb.input));
        workers.forEach(worker -> packetQueues.add(worker.input));
        activePacketQueues = List.copyOf(packetQueues);
        activeResultQueues = workers.stream().map(worker -> worker.output).toList();

        Path destination = Path.of(outputFile).toAbsolutePath().normalize();
        Path parent = destination.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IOException("Output directory does not exist: " + parent);
        }
        Path temporaryOutput = Files.createTempFile(parent, "." + destination.getFileName() + ".", ".partial");
        Thread writer = new Thread(() -> writeCompletedPackets(inputFile, temporaryOutput.toString(), workers),
                "dpi-pcap-writer");
        workers.forEach(worker -> worker.thread.start());
        loadBalancers.forEach(lb -> lb.thread.start());
        writer.start();

        IOException producerError = null;
        long packetId = 0;
        try (PcapReader reader = new PcapReader(inputFile)) {
            while (!stopRequested.get()) {
                PcapReader.RawPacket raw = new PcapReader.RawPacket();
                if (!reader.readNextPacket(raw)) {
                    break;
                }
                PacketParser.ParsedPacket packet = new PacketParser.ParsedPacket();
                boolean valid = PacketParser.parse(raw, packet);
                if (!valid) {
                    packet = null;
                }
                PacketJob job = new PacketJob(packetId++, raw, packet);
                totalPackets.incrementAndGet();
                totalBytes.addAndGet(raw.data.length);
                if (packet != null) {
                    if (packet.hasTcp) tcpPackets.incrementAndGet();
                    else if (packet.hasUdp) udpPackets.incrementAndGet();
                    else otherPackets.incrementAndGet();
                } else {
                    otherPackets.incrementAndGet();
                }
                DpiTypes.FiveTuple tuple = packet == null ? null : tupleOf(packet);
                int lbIndex = tuple == null
                        ? Math.floorMod(Long.hashCode(job.id), loadBalancers.size())
                        : workerIndex(ConnectionTracker.canonical(tuple), workerCount) / config.fpsPerLb;
                loadBalancers.get(lbIndex).input.put(job);
                if (config.verbose && packetId % 10_000 == 0) {
                    System.out.println("[DPI] Read " + packetId + " packets");
                }
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            producerError = new IOException("Packet processing was interrupted", exception);
        } catch (IOException exception) {
            producerError = exception;
        } catch (RuntimeException exception) {
            producerError = new IOException("Packet producer failed", exception);
        } finally {
            loadBalancers.forEach(lb -> lb.input.close());
        }

        for (LoadBalancer loadBalancer : loadBalancers) {
            join(loadBalancer.thread, "load balancer");
        }
        for (Worker worker : workers) {
            join(worker.thread, "fast-path processor");
        }
        workers.forEach(worker -> worker.output.close());
        join(writer, "output writer");

        if (processingError != null) {
            Files.deleteIfExists(temporaryOutput);
            throw processingError;
        }
        if (producerError != null) {
            Files.deleteIfExists(temporaryOutput);
            throw producerError;
        }
        for (ConnectionTracker tracker : trackers) {
            tracker.cleanupStale(java.time.Duration.ofSeconds(300));
        }
        try {
            Files.move(temporaryOutput, destination, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (java.nio.file.AtomicMoveNotSupportedException exception) {
            try {
                Files.move(temporaryOutput, destination, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException moveException) {
                Files.deleteIfExists(temporaryOutput);
                throw moveException;
            }
        } catch (IOException exception) {
            Files.deleteIfExists(temporaryOutput);
            throw exception;
        }
        activePacketQueues = List.of();
        activeResultQueues = List.of();
    }

    private void writeCompletedPackets(String inputFile, String outputFile, List<Worker> workers) {
        Map<Long, PacketJob> waiting = new TreeMap<>();
        long nextId = 0;
        try (PcapReader input = new PcapReader(inputFile);
             DataOutputStream output = new DataOutputStream(new FileOutputStream(outputFile))) {
            PcapReader.GlobalHeader header = input.getGlobalHeader();
            output.write(header.rawHeader);
            int completedWorkers = 0;
            while (completedWorkers < workers.size()) {
                boolean gotJob = false;
                for (Worker worker : workers) {
                    if (worker.finished) {
                        continue;
                    }
                    PacketJob job = worker.output.pollAvailable();
                    if (job == PacketJob.END) {
                        worker.finished = true;
                        completedWorkers++;
                    } else if (job != null) {
                        waiting.put(job.id, job);
                        gotJob = true;
                    }
                }
                while (waiting.containsKey(nextId)) {
                    PacketJob job = waiting.remove(nextId++);
                    if (!job.drop) {
                        writePacket(output, job.raw, header.littleEndian);
                        forwardedPackets.incrementAndGet();
                    } else {
                        droppedPackets.incrementAndGet();
                    }
                }
                if (!gotJob && completedWorkers < workers.size()) {
                    Thread.sleep(1);
                }
            }
            while (!waiting.isEmpty()) {
                PacketJob job = waiting.remove(nextId++);
                if (!job.drop) {
                    writePacket(output, job.raw, header.littleEndian);
                    forwardedPackets.incrementAndGet();
                } else {
                    droppedPackets.incrementAndGet();
                }
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            processingError = new IOException("Output writer was interrupted", exception);
            abortPipeline();
        } catch (IOException | RuntimeException exception) {
            processingError = exception instanceof IOException io
                    ? io : new IOException("Failed to write output PCAP", exception);
            abortPipeline();
        }
    }

    private final class LoadBalancer {
        private final int id;
        private final List<Worker> workers;
        private final ThreadSafeQueue<PacketJob> input;
        private final Thread thread;
        private final LongAdder packetsReceived = new LongAdder();
        private final LongAdder packetsDispatched = new LongAdder();
        private final LongAdder[] perWorkerCounts;

        private LoadBalancer(int id, List<Worker> workers, int queueCapacity) {
            this.id = id;
            this.workers = workers;
            this.input = new ThreadSafeQueue<>(queueCapacity);
            this.perWorkerCounts = new LongAdder[workers.size()];
            java.util.Arrays.setAll(perWorkerCounts, ignored -> new LongAdder());
            this.thread = new Thread(this::run, "dpi-load-balancer-" + id);
        }

        private void run() {
            try {
                PacketJob job;
                while ((job = input.take()) != null) {
                    packetsReceived.increment();
                    int workerIndex = job.parsed == null
                            ? Math.floorMod(Long.hashCode(job.id), workers.size())
                            : workerIndex(ConnectionTracker.canonical(tupleOf(job.parsed)),
                                    config.numLoadBalancers * config.fpsPerLb) % workers.size();
                    workers.get(workerIndex).input.put(job);
                    packetsDispatched.increment();
                    perWorkerCounts[workerIndex].increment();
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                recordWorkerFailure("Load balancer interrupted", exception);
            } catch (RuntimeException exception) {
                recordWorkerFailure("Load balancer failed", exception);
            } finally {
                workers.forEach(worker -> worker.input.close());
            }
        }
    }

    private final class Worker {
        private final int id;
        private final ConnectionTracker tracker;
        private final ThreadSafeQueue<PacketJob> input;
        private final ResultQueue output = new ResultQueue();
        private final Thread thread;
        private volatile boolean finished;
        private final LongAdder packetsProcessed = new LongAdder();
        private final LongAdder packetsForwarded = new LongAdder();
        private final LongAdder packetsDropped = new LongAdder();
        private final LongAdder sniExtractions = new LongAdder();
        private final LongAdder classificationHits = new LongAdder();

        private Worker(int id, ConnectionTracker tracker, int queueCapacity) {
            this.id = id;
            this.tracker = tracker;
            this.input = new ThreadSafeQueue<>(queueCapacity);
            this.output.capacity = queueCapacity;
            this.thread = new Thread(this::run, "dpi-fast-path-" + id);
        }

        private void run() {
            try {
                PacketJob job;
                while ((job = input.take()) != null) {
                    packetsProcessed.increment();
                    inspect(job);
                    if (job.drop) packetsDropped.increment();
                    else packetsForwarded.increment();
                    output.put(job);
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                recordWorkerFailure("Fast-path processor interrupted", exception);
            } catch (RuntimeException exception) {
                recordWorkerFailure("Fast-path processor failed", exception);
            } finally {
                output.close();
            }
        }

        private void inspect(PacketJob job) {
            PacketParser.ParsedPacket packet = job.parsed;
            if (packet == null || !packet.hasIp || (!packet.hasTcp && !packet.hasUdp)) {
                return;
            }
            DpiTypes.FiveTuple tuple = tupleOf(packet);
            DpiTypes.FiveTuple canonical = ConnectionTracker.canonical(tuple);
            boolean outbound = tuple.equals(canonical);
            ConnectionTracker.Connection connection = tracker.updateConnection(
                    canonical, job.raw.data.length, outbound, packet.tcpFlags);

            String domain = "";
            DpiTypes.AppType app = connection.appType;
            if (packet.hasTcp && packet.payloadLength > 0
                    && (packet.srcPort == 443 || packet.destPort == 443)) {
                Optional<String> sni = SniExtractor.extract(packet.payloadData);
                if (sni.isPresent()) {
                    sniExtractions.increment();
                    domain = sni.get();
                    app = DpiTypes.sniToAppType(domain);
                } else if (app == DpiTypes.AppType.UNKNOWN) {
                    app = DpiTypes.AppType.HTTPS;
                }
            }
            if (packet.hasTcp && packet.payloadLength > 0
                    && (packet.srcPort == 80 || packet.destPort == 80)) {
                Optional<String> host = SniExtractor.extractHttpHost(packet.payloadData);
                if (host.isPresent()) {
                    domain = host.get();
                    app = DpiTypes.sniToAppType(domain);
                } else if (app == DpiTypes.AppType.UNKNOWN) {
                    app = DpiTypes.AppType.HTTP;
                }
            }
            if (packet.hasUdp && packet.payloadLength > 0
                    && (packet.srcPort == 53 || packet.destPort == 53)) {
                Optional<String> query = SniExtractor.extractDnsQuery(packet.payloadData);
                if (query.isPresent()) {
                    domain = query.get();
                }
                app = DpiTypes.AppType.DNS;
            } else if (packet.hasUdp && packet.payloadLength > 0
                    && (packet.srcPort == 443 || packet.destPort == 443)) {
                Optional<String> sni = SniExtractor.extractQuicSni(packet.payloadData);
                if (sni.isPresent()) {
                    domain = sni.get();
                    app = DpiTypes.sniToAppType(domain);
                } else if (app == DpiTypes.AppType.UNKNOWN) {
                    app = DpiTypes.AppType.QUIC;
                }
            }
            if (app != DpiTypes.AppType.UNKNOWN) {
                tracker.classifyConnection(canonical, app, domain);
                appStats.computeIfAbsent(app, ignored -> new LongAdder()).increment();
                classificationHits.increment();
            }
            String effectiveDomain = domain.isBlank() ? connection.sni : domain;
            Optional<RuleManager.BlockReason> reason =
                    rules.shouldBlock(packet.srcIpValue, packet.destPort, app, effectiveDomain);
            if (reason.isPresent() || connection.action == DpiTypes.PacketAction.DROP) {
                job.drop = true;
                tracker.blockConnection(canonical);
                if (config.verbose && reason.isPresent()) {
                    System.out.println("[DPI] Dropped " + tuple + " (" + reason.get().type()
                            + ": " + reason.get().detail() + ")");
                }
            }
        }
    }

    private static final class PacketJob {
        private static final PacketJob END = new PacketJob(-1, null, null);
        private final long id;
        private final PcapReader.RawPacket raw;
        private final PacketParser.ParsedPacket parsed;
        private volatile boolean drop;

        private PacketJob(long id, PcapReader.RawPacket raw, PacketParser.ParsedPacket parsed) {
            this.id = id;
            this.raw = raw;
            this.parsed = parsed;
        }
    }

    private static final class ResultQueue {
        private final java.util.ArrayDeque<PacketJob> queue = new java.util.ArrayDeque<>();
        private int capacity;
        private boolean closed;

        private synchronized void put(PacketJob job) throws InterruptedException {
            while (queue.size() >= capacity && !closed) {
                wait();
            }
            if (closed) {
                throw new IllegalStateException("Result queue closed before packet result was written");
            }
            queue.addLast(job);
            notifyAll();
        }

        private synchronized PacketJob pollAvailable() {
            PacketJob job = queue.pollFirst();
            if (job == null && closed) {
                return PacketJob.END;
            }
            notifyAll();
            return job;
        }

        private synchronized void close() {
            closed = true;
            notifyAll();
        }
    }

    private void recordWorkerFailure(String message, Exception exception) {
        synchronized (this) {
            if (processingError == null) {
                processingError = new IOException(message, exception);
            }
        }
        stopRequested.set(true);
        abortPipeline();
    }

    private void abortPipeline() {
        activePacketQueues.forEach(ThreadSafeQueue::close);
        activeResultQueues.forEach(ResultQueue::close);
    }

    private void resetStats() {
        totalPackets.set(0);
        totalBytes.set(0);
        forwardedPackets.set(0);
        droppedPackets.set(0);
        tcpPackets.set(0);
        udpPackets.set(0);
        otherPackets.set(0);
        appStats.clear();
    }

    private static DpiTypes.FiveTuple tupleOf(PacketParser.ParsedPacket packet) {
        return new DpiTypes.FiveTuple(packet.srcIpValue, packet.destIpValue,
                packet.srcPort, packet.destPort, packet.protocol);
    }

    private static int workerIndex(DpiTypes.FiveTuple tuple, int workerCount) {
        int hash = tuple.hashCode();
        return Math.floorMod(hash ^ (hash >>> 16), workerCount);
    }

    private static void join(Thread thread, String role) throws IOException {
        try {
            thread.join();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for " + role, exception);
        }
    }

    private static void writePacket(DataOutputStream output, PcapReader.RawPacket raw,
            boolean littleEndian) throws IOException {
        writeUInt32(output, raw.header.tsSec, littleEndian);
        writeUInt32(output, raw.header.tsUsec, littleEndian);
        writeUInt32(output, raw.header.inclLen, littleEndian);
        writeUInt32(output, raw.header.origLen, littleEndian);
        output.write(raw.data);
    }

    private static void writeUInt32(DataOutputStream output, long value, boolean littleEndian)
            throws IOException {
        if (littleEndian) {
            output.writeByte((int) value);
            output.writeByte((int) (value >>> 8));
            output.writeByte((int) (value >>> 16));
            output.writeByte((int) (value >>> 24));
        } else {
            output.writeByte((int) (value >>> 24));
            output.writeByte((int) (value >>> 16));
            output.writeByte((int) (value >>> 8));
            output.writeByte((int) value);
        }
    }

    private static String requireValue(String[] args, int index, String option) {
        if (index >= args.length) {
            throw new IllegalArgumentException("Missing value for " + option);
        }
        return args[index];
    }

    private static int parseInt(String value, String option) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("Invalid integer for " + option + ": " + value, exception);
        }
    }

    private static void printUsage() {
        System.out.println("""
                DPI Engine - Deep Packet Inspection System
                Usage: DpiEngine <input.pcap> <output.pcap> [options]
                  --block-ip <ip>          Block source IPv4 address
                  --unblock-ip <ip>        Remove source IP rule
                  --block-app <app>        Block an application
                  --unblock-app <app>      Remove application rule
                  --block-domain <domain>  Block exact or *.wildcard domain
                  --unblock-domain <dom>   Remove domain rule
                  --block-port <port>      Block destination port
                  --unblock-port <port>    Remove destination port rule
                  --rules <file>           Load rule file
                  --save-rules <file>      Save rules after processing
                  --lbs <n>                Number of load balancer threads (default 2)
                  --fps <n>                Fast-path threads per load balancer (default 2)
                  --queue-size <n>         Capacity of each processing queue
                  --max-connections <n>    Per-processor connection limit
                  --report                 Print classification report
                  --report-file <file>     Write reports to a file
                  --verbose                Log per-packet decisions
                """);
    }
}
