// Main.java
//
// PHASE 10 - FINAL VERSION.
// Uses ArgParser for command-line configuration (input/output files,
// number of workers, and blocking rules), times the run, and prints
// the polished final report.
//
// Pipeline (unchanged from Phase 9):
//   ReaderThread --> LoadBalancerThread --> Worker[0..N] --> WriterThread

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class Main {
    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws InterruptedException {

        ArgParser config = ArgParser.parse(args);

        System.out.println("Input:   " + config.inputFile);
        System.out.println("Output:  " + config.outputFile);
        System.out.println("Workers: " + config.numWorkers);

        // ---- Build the rule set from command-line flags ----
        RuleManager rules = new RuleManager();
        for (AppType app : config.blockedApps) {
            rules.blockApp(app);
            System.out.println("Blocking app: " + app);
        }
        for (String domain : config.blockedDomains) {
            rules.blockDomainContaining(domain);
            System.out.println("Blocking domain containing: " + domain);
        }
        for (String ip : config.blockedIps) {
            rules.blockIp(ip);
            System.out.println("Blocking IP: " + ip);
        }
        System.out.println("----------------------------------------");

        long startTime = System.currentTimeMillis();

        // ---- Build the pipeline (same structure as Phase 9) ----
        BlockingQueue<Packet> readQueue = new LinkedBlockingQueue<>();

        BlockingQueue<Packet>[] workerQueues = new BlockingQueue[config.numWorkers];
        for (int i = 0; i < config.numWorkers; i++) {
            workerQueues[i] = new LinkedBlockingQueue<>();
        }

        BlockingQueue<Packet> writeQueue = new LinkedBlockingQueue<>();

        FlowTracker tracker = new FlowTracker();

        ReaderThread reader = new ReaderThread(config.inputFile, readQueue);
        LoadBalancerThread loadBalancer = new LoadBalancerThread(readQueue, workerQueues);

        WorkerThread[] workers = new WorkerThread[config.numWorkers];
        for (int i = 0; i < config.numWorkers; i++) {
            workers[i] = new WorkerThread("Worker-" + i, workerQueues[i], writeQueue, tracker, rules);
        }

        WriterThread writer = new WriterThread(config.outputFile, writeQueue, config.numWorkers);

        writer.start();
        for (WorkerThread w : workers) {
            w.start();
        }
        loadBalancer.start();
        reader.start();

        reader.join();
        loadBalancer.join();
        for (WorkerThread w : workers) {
            w.join();
        }
        writer.join();

        long elapsed = System.currentTimeMillis() - startTime;

        ReportGenerator.printReport(
                (int) writer.totalPackets.get(),
                (int) writer.forwardedPackets.get(),
                (int) writer.droppedPackets.get(),
                tracker,
                elapsed);
    }
}