/* 
 * Copyright (c) 2016, LamaCrypt
 * All rights reserved.
 *
 * The LamaCrypt client software and its source code are available
 * under the LamaCrypt Software License: 
 * https://www.lamacrypt.ch/lcsl.php
 */
package ch.lamacrypt.internal.network;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * Contains general purpose methods related to TLS
 *
 * @author LamaGuy
 */
public class GPTLS {
        /**
     * Sets the supported TLS version and cipher suite(s)
     *
     * @param socket SSLSocket to act upon
     */
    public static void setTLSParams(SSLSocket socket) {
        socket.setEnabledProtocols(new String[]{"TLSv1.2"});
        socket.setEnabledCipherSuites(new String[]{
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"});
    }

    /**
     * Returns an SSLContext object which instantiates TLS
     *
     * @return SSLContext for TLS
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.KeyManagementException
     */
    public static SSLContext getContext() throws NoSuchAlgorithmException, KeyManagementException {
        // creates the SSLContext needed to instantiate the SSLSocket
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        return sslContext;
    }
}
