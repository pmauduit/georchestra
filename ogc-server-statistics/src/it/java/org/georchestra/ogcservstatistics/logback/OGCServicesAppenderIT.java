package org.georchestra.ogcservstatistics.logback;

import ch.qos.logback.classic.LoggerContext;
import org.georchestra.ogcservstatistics.dataservices.DataServicesConfiguration;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;


public class OGCServicesAppenderIT {

    private OGCServicesAppender appender;

    private static Logger logger = LoggerFactory.getLogger(OGCServicesAppenderIT.class);

    @Before
    public void setUp() {
        appender = new OGCServicesAppender();
        appender.start();

    }
    @Test
    public void testAppender() {
        LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
        lc.start();
        lc.getLogger(this.getClass()).addAppender(appender);

        logger.info("");
    }
}
