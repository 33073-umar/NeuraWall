package cic.cs.unb.ca.jnetpcap;

import cic.cs.unb.ca.jnetpcap.*;
import org.jnetpcap.PcapClosedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;

public class PcapToCsvCli {
    private static final Logger logger = LoggerFactory.getLogger(PcapToCsvCli.class);
    private static final String FILE_SEP = System.getProperty("file.separator");
    private static final String FLOW_SUFFIX = "_flows.csv";
    public static final String PROPERTY_FLOW = "file_flow";

    private final PropertyChangeSupport support;

    public PcapToCsvCli() {
        this.support = new PropertyChangeSupport(this);
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java -cp <jar_file> cic.cs.unb.ca.jnetpcap.PcapToCsvCli <input_pcap_file> <output_directory>");
            System.exit(1);
        }

        String inputPcapFile = args[0];
        String outputDir = args[1];

        PcapToCsvCli pcapToCsvCli = new PcapToCsvCli();
        try {
            pcapToCsvCli.runFlowGeneration(inputPcapFile, outputDir);
            System.out.println("Flow features generated successfully in: " + outputDir);
        } catch (IOException e) {
            System.err.println("Error processing pcap file: " + e.getMessage());
        }
    }

    public void addPropertyChangeListener(PropertyChangeListener listener) {
        support.addPropertyChangeListener(listener);
    }

    public void removePropertyChangeListener(PropertyChangeListener listener) {
        support.removePropertyChangeListener(listener);
    }

    private void runFlowGeneration(String inputFile, String outputDir) throws IOException {
        if (inputFile == null || outputDir == null) {
            return;
        }

        // Prepare output path and file name
        Path inputPath = Paths.get(inputFile);
        String fileName = inputPath.getFileName().toString();
        if (!outputDir.endsWith(FILE_SEP)) {
            outputDir += FILE_SEP;
        }
        File outputFile = new File(outputDir + fileName + FLOW_SUFFIX);

        // Remove existing output file if it exists
        if (outputFile.exists()) {
            if (!outputFile.delete()) {
                System.out.println("Existing output file could not be deleted");
            }
        }

        // Initialize FlowGenerator and add a FlowListener
        FlowGenerator flowGen = new FlowGenerator(true, 120000000L, 5000000L);
        flowGen.addFlowListener(new FlowListener(fileName));

        PacketReader packetReader = new PacketReader(inputFile, true, false); // Assuming readIP4 = true and readIP6 = false

        System.out.println("Working on... " + inputFile);
        logger.debug("Working on... {}", inputFile);

        int nValid = 0;
        int nTotal = 0;
        int nDiscarded = 0;

        // Process packets in the pcap file
        try {
            while (true) {
                BasicPacketInfo packet = packetReader.nextPacket();
                nTotal++;
                if (packet != null) {
                    flowGen.addPacket(packet);
                    nValid++;
                } else {
                    nDiscarded++;
                }
            }
        } catch (PcapClosedException e) {
            // End of pcap file reached
        }

        // Dump flow features to CSV
        flowGen.dumpLabeledCurrentFlow(outputFile.getPath(), FlowFeature.getHeader());

        // Output statistics
        long lines = countLines(outputFile.getPath());
        System.out.printf("Done! Total %d flows%n", lines);
        System.out.printf("Packets stats: Total=%d, Valid=%d, Discarded=%d%n", nTotal, nValid, nDiscarded);
    }

    private static long countLines(String filePath) {
        try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(filePath))) {
            return reader.lines().count();
        } catch (IOException e) {
            System.err.println("Error counting lines in file: " + e.getMessage());
            return 0;
        }
    }

    class FlowListener implements FlowGenListener {

        private String fileName;

        FlowListener(String fileName) {
            this.fileName = fileName;
        }

        @Override
        public void onFlowGenerated(BasicFlow flow) {
            firePropertyChange(PROPERTY_FLOW, fileName, flow);
        }
    }

    private void firePropertyChange(String propertyName, String fileName, BasicFlow flow) {
        support.firePropertyChange(propertyName, fileName, flow);
    }
}
