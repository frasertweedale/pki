package org.dogtagpki.est;

import java.io.File;
import java.io.FileReader;
import java.util.Properties;
import java.util.TreeMap;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

/**
 * Engine that manages the EST backend(s) according to configuration.
 *
 * @author Fraser Tweedale
 */
@WebListener
public class ESTEngine implements ServletContextListener {

    private static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ESTEngine.class);

    // maintain a map of instances indexed by context path
    private static TreeMap<HostAndContextPath, ESTEngine> INSTANCES = new TreeMap<>();

    public static ESTEngine getInstance(ServletContext servletContext) {
        return INSTANCES.get(makeKey(servletContext));
    }

    private static HostAndContextPath makeKey(ServletContext ctx) {
        return new HostAndContextPath(ctx.getVirtualServerName(), ctx.getContextPath());
    }

    private ESTBackend backend;

    public ESTBackend getBackend() {
        return backend;
    }

    public void start(String contextPath) throws Throwable {
        logger.info("Starting EST engine");

        String contextPathDirName = "".equals(contextPath) ? "ROOT" : contextPath.substring(1);
        String catalinaBase = System.getProperty("catalina.base");
        String serverConfDir = catalinaBase + File.separator + "conf";
        String estConfDir = serverConfDir + File.separator + contextPathDirName;

        logger.info("EST configuration directory: " + estConfDir);

        initBackend(estConfDir + File.separator + "backend.conf");

        logger.info("EST engine started");
    }

    public void stop() throws Throwable {
        logger.info("Stopping EST engine");

        if (backend != null) {
            backend.stop();
        }

        logger.info("EST engine stopped");
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        String contextPath = event.getServletContext().getContextPath();
        try {
            start(contextPath);
        } catch (Throwable e) {
            logger.error("Unable to start EST engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to start EST engine: " + e.getMessage(), e);
        }
        // initialization succeeded; add to map
        INSTANCES.put(makeKey(event.getServletContext()), this);
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        try {
            stop();
        } catch (Throwable e) {
            logger.error("Unable to stop EST engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to stop EST engine: " + e.getMessage(), e);
        }
        INSTANCES.remove(event.getServletContext());
    }

    private void initBackend(String filename) throws Throwable {
        File file = new File(filename);
        if (!file.exists()) {
            throw new RuntimeException("Missing backend configuration file " + filename);
        }

        logger.info("Loading EST backend config from " + filename);
        Properties props = new Properties();
        try (FileReader reader = new FileReader(file)) {
            props.load(reader);
        }
        ESTBackendConfig config = ESTBackendConfig.fromProperties(props);

        logger.info("Initializing EST backend");

        String className = config.getClassName();
        Class<ESTBackend> backendClass = (Class<ESTBackend>) Class.forName(className);

        backend = backendClass.getDeclaredConstructor().newInstance();
        backend.setConfig(config);
        backend.start();
    }

    private static class HostAndContextPath implements Comparable<HostAndContextPath> {
        public String host;
        public String contextPath;

        public HostAndContextPath(String host, String contextPath) {
            this.host = host;
            this.contextPath = contextPath;
        }

        public int compareTo(HostAndContextPath other) {
            int r = this.host.compareTo(other.host);
            if (r == 0) r = this.contextPath.compareTo(other.contextPath);
            return r;
        }
    }

}
