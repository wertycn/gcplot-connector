package com.gcplot.connector;

import com.beust.jcommander.Parameter;
import com.google.common.base.Strings;
import net.openhft.chronicle.map.ChronicleMapBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.ConcurrentMap;

/**
 * @author <a href="mailto:art.dm.ser@gmail.com">Artem Dmitriev</a>
 *         3/28/17
 */
public class Bootstrap {
    private static final Logger LOG = LoggerFactory.getLogger(Bootstrap.class);

    @Parameter(names = { "-logs_dir" }, description = "Directory where log files are located.")
    private String logsDir;
    @Parameter(names = { "-gcp_host" }, description = "GCPlot API host address.")
    private String gcpHost;
    @Parameter(names = { "-data_dir" }, description = "Connector data directory.")
    private String dataDir;

    private ConcurrentMap<String, Boolean> processedFiles;

    public void init() throws IOException {
        if (Strings.isNullOrEmpty(dataDir) || new File(dataDir).exists()) {
            LOG.error("Data directory '{}' does not exist.", dataDir);
            return;
        }
        if (Strings.isNullOrEmpty(gcpHost)) {
            LOG.error("GCPlot host address cannot be empty!");
            return;
        }
        File processedFilesDb = new File(dataDir, "processed.dat");
        if (!processedFilesDb.exists()) {
            processedFilesDb.createNewFile();
        }
        ChronicleMapBuilder<String, Boolean> builder =
                ChronicleMapBuilder.of(String.class, Boolean.class);
        processedFiles = builder.createPersistedTo(processedFilesDb);


    }

    public static void main(String[] args) {
        try {
            LOG.info("Starting GCPlot connector.");


        } catch (Throwable t) {
            LOG.error(t.getMessage(), t);
        }
    }

}
