package org.georchestra.ogcservstatistics.logback;

import ch.qos.logback.core.AppenderBase;
import org.georchestra.ogcservstatistics.dataservices.DataServicesConfiguration;
import org.georchestra.ogcservstatistics.dataservices.InsertCommand;
import org.georchestra.ogcservstatistics.common.OGCServiceParser;
import org.slf4j.event.LoggingEvent;

import java.sql.Connection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class OGCServicesAppender<E> extends AppenderBase<E> {

    private static DataServicesConfiguration dataServiceConfiguration = DataServicesConfiguration.getInstance();

    @Override
    protected void append(E o) {
        CompletableFuture.runAsync(() -> {
            try {
                // let it finish if the task was issued even if the appender was closed after
                // the fact
                if (!this.isStarted()) {
                    return;
                }
                // o is a ch.qos.logback.classic.spi.LoggingEvent object
                LoggingEvent evt = (LoggingEvent) o;
                String msg = evt.getMessage();
                List<Map<String, Object>> logList = OGCServiceParser.parseLog(msg);
                insert(logList);
            } catch (Exception ex) {

            }
        });
    }

    private void insert(List<Map<String, Object>> ogcServiceRecords) {

        try (Connection c = dataServiceConfiguration.getConnection()) {
            for (Map<String, Object> entry : ogcServiceRecords) {
                InsertCommand cmd = new InsertCommand();
                cmd.setConnection(c);
                cmd.setRowValues(entry);
                cmd.execute();
            }
        } catch (Exception e) {

        }

    }
}
