//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.IOException;
import java.util.Properties;
import java.util.Optional;
import java.util.function.Consumer;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPDN;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.controls.LDAPPersistSearchControl;
import netscape.ldap.util.DN;

import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.certsrv.ldap.ELdapException;

/**
 * Monitor LDAP for ACME configuration changes.
 */
class ACMEEngineConfigLDAPSource
        extends ACMEEngineConfigSource
        implements Runnable {

    static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEEngine.class);

    // thread management
    Thread monitorThread = null;
    boolean stopped = false;

    // LDAP configuration
    private String entryDNString = null;
    LdapBoundConnFactory connFactory = null;

    // Cached config values, so we only send values that actually changed
    // Values start as empty so that the initial read causes the initial
    // values to be sent.
    Optional<Boolean> cacheEnabled = Optional.empty();

    public void init(
            Properties cfg,
            Consumer<Boolean> setEnabled)
            throws Exception {
        init(setEnabled);

        // load LDAP config
        entryDNString = cfg.getProperty("basedn");
        if (entryDNString == null)
            throw new RuntimeException("ACMEEngineConfigLDAPSource: entryDNString not specified");

        String path = cfg.getProperty("configFile");
        if (path == null)
            throw new RuntimeException("ACMEEngineConfigLDAPSource: configFile not specified");

        PropConfigStore cs = new PropConfigStore(new FileConfigStore(path));
        cs.load();
        LDAPConfig dbCfg = cs.getSubStore("internaldb", LDAPConfig.class);
        connFactory = new LdapBoundConnFactory("acme");
        connFactory.init(
            cs, dbCfg, IPasswordStore.getPasswordStore("acme", cs.getProperties()));

        // start monitor thread
        stopped = false;
        monitorThread = new Thread(this, "ACMEEngineConfigLDAPSource");
        monitorThread.start();
    }

    void readEntry(LDAPEntry entry) {
        // default values
        Boolean enabled = true;

        // read values
        // TODO

        // send changed values and update cache
        Optional<Boolean> v = Optional.of(enabled);
        if (!cacheEnabled.equals(v)) {
            setEnabled.accept(enabled);
            cacheEnabled = v;
        }
    }

    public void run() {
        LDAPPersistSearchControl persistCtrl =
            new LDAPPersistSearchControl(
                LDAPPersistSearchControl.MODIFY,  // change types
                false,  // return current entry, then watch for changes
                false,  // we don't need the entry change control in results
                true    // criticial extension
            );

        LDAPConnection conn = null;

        while (!stopped) {
            try {
                conn = connFactory.getConn();
                LDAPSearchConstraints cons = conn.getSearchConstraints();
                cons.setServerControls(persistCtrl);
                cons.setBatchSize(1);

                LDAPSearchResults results = conn.search(
                    entryDNString, LDAPConnection.SCOPE_BASE,
                    "(objectclass=*)", null /*attrs*/, false, cons);

                while (!stopped && results.hasMoreElements()) {
                    LDAPEntry entry = results.next();
                    readEntry(entry);
                }
            } catch (ELdapException e) {
                logger.warn("ACMEEngineConfigLDAPSource: failed to get LDAPConnection. Retrying in 1 second.");
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            } catch (LDAPException e) {
                logger.error("ACMEEngineConfigLDAPSource: Caught exception: " + e, e);
            } finally {
                if (conn != null) {
                    try {
                        connFactory.returnConn(conn);
                        conn = null;
                    } catch (Exception e) {
                        logger.error("ACMEEngineConfigLDAPSource: Error releasing the LDAPConnection" + e, e);
                    }
                }
            }
        }
        logger.info("ACMEEngineConfigLDAPSource: monitor thread stopping.");
        monitorThread = null;
    }

    @Override
    public void shutdown() {
        stopped = true;
        if (monitorThread != null) {
            logger.info("ACMEEngineConfigSource.shutdown(): interrupting monitor thread");
            monitorThread.interrupt();
            monitorThread = null;
        }
    }
}
