/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kafka.common.security.auth;

import javax.security.auth.x500.X500Principal;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.network.Authenticator;
import org.apache.kafka.common.network.TransportLayer;
import org.apache.kafka.common.security.authenticator.DefaultKafkaPrincipalBuilder;
import org.apache.kafka.common.security.kerberos.KerberosName;
import org.apache.kafka.common.security.kerberos.KerberosShortNamer;
import org.apache.kafka.common.security.scram.internals.ScramMechanism;
import org.apache.kafka.common.security.ssl.SslPrincipalMapper;
import org.easymock.EasyMock;
import org.easymock.EasyMockSupport;
import org.junit.Test;
import org.mockito.Mockito;

import javax.net.ssl.SSLSession;
import javax.security.sasl.SaslServer;
import java.net.InetAddress;
import java.security.Principal;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


public class DefaultKafkaPrincipalBuilderTest extends EasyMockSupport {

    @Test
    @SuppressWarnings("deprecation")
    public void testUseOldPrincipalBuilderForPlaintextIfProvided() throws Exception {
        TransportLayer transportLayer = mock(TransportLayer.class);
        Authenticator authenticator = mock(Authenticator.class);
        PrincipalBuilder oldPrincipalBuilder = mock(PrincipalBuilder.class);

        EasyMock.expect(oldPrincipalBuilder.buildPrincipal(transportLayer, authenticator))
                .andReturn(new DummyPrincipal("foo"));
        oldPrincipalBuilder.close();
        EasyMock.expectLastCall();

        replayAll();

        DefaultKafkaPrincipalBuilder builder = DefaultKafkaPrincipalBuilder.fromOldPrincipalBuilder(authenticator,
                transportLayer, oldPrincipalBuilder, null);

        KafkaPrincipal principal = builder.build(new PlaintextAuthenticationContext(
                InetAddress.getLocalHost(), SecurityProtocol.PLAINTEXT.name()));
        assertEquals(KafkaPrincipal.USER_TYPE, principal.getPrincipalType());
        assertEquals("foo", principal.getName());

        builder.close();
        verifyAll();
    }

    @Test
    public void testReturnAnonymousPrincipalForPlaintext() throws Exception {
        try (DefaultKafkaPrincipalBuilder builder = new DefaultKafkaPrincipalBuilder(null, null)) {
            assertEquals(KafkaPrincipal.ANONYMOUS, builder.build(
                    new PlaintextAuthenticationContext(InetAddress.getLocalHost(), SecurityProtocol.PLAINTEXT.name())));
        }
    }

    @Test
    @SuppressWarnings("deprecation")
    public void testUseOldPrincipalBuilderForSslIfProvided() throws Exception {
        TransportLayer transportLayer = mock(TransportLayer.class);
        Authenticator authenticator = mock(Authenticator.class);
        PrincipalBuilder oldPrincipalBuilder = mock(PrincipalBuilder.class);
        SSLSession session = mock(SSLSession.class);

        EasyMock.expect(oldPrincipalBuilder.buildPrincipal(transportLayer, authenticator))
                .andReturn(new DummyPrincipal("foo"));
        oldPrincipalBuilder.close();
        EasyMock.expectLastCall();

        replayAll();

        DefaultKafkaPrincipalBuilder builder = DefaultKafkaPrincipalBuilder.fromOldPrincipalBuilder(authenticator,
                transportLayer, oldPrincipalBuilder, null);

        KafkaPrincipal principal = builder.build(
                new SslAuthenticationContext(session, InetAddress.getLocalHost(), SecurityProtocol.PLAINTEXT.name()));
        assertEquals(KafkaPrincipal.USER_TYPE, principal.getPrincipalType());
        assertEquals("foo", principal.getName());

        builder.close();
        verifyAll();
    }

    @Test
    public void testUseSessionPeerPrincipalForSsl() throws Exception {
        SSLSession session = Mockito.mock(SSLSession.class);

        when(session.getPeerPrincipal()).thenReturn(new DummyPrincipal("foo"));

        DefaultKafkaPrincipalBuilder builder = new DefaultKafkaPrincipalBuilder(null, null);

        KafkaPrincipal principal = builder.build(
                new SslAuthenticationContext(session, InetAddress.getLocalHost(), SecurityProtocol.PLAINTEXT.name()));
        assertEquals(KafkaPrincipal.USER_TYPE, principal.getPrincipalType());
        assertEquals("foo", principal.getName());

        builder.close();
        verify(session, atLeastOnce()).getPeerPrincipal();
    }

    @Test
    public void testPrincipalIfSSLPeerIsNotAuthenticated() throws Exception {
        SSLSession session = Mockito.mock(SSLSession.class);

        when(session.getPeerPrincipal()).thenReturn(KafkaPrincipal.ANONYMOUS);

        DefaultKafkaPrincipalBuilder builder = new DefaultKafkaPrincipalBuilder(null, null);

        KafkaPrincipal principal = builder.build(
                new SslAuthenticationContext(session, InetAddress.getLocalHost(), SecurityProtocol.PLAINTEXT.name()));
        assertEquals(KafkaPrincipal.ANONYMOUS, principal);

        builder.close();
        verify(session, atLeastOnce()).getPeerPrincipal();
    }


    @Test
    public void testPrincipalWithSslPrincipalMapper() throws Exception {
        SSLSession session = Mockito.mock(SSLSession.class);

        when(session.getPeerPrincipal()).thenReturn(new X500Principal("CN=Duke, OU=ServiceUsers, O=Org, C=US"))
                .thenReturn(new X500Principal("CN=Duke, OU=SME, O=mycp, L=Fulton, ST=MD, C=US"))
                .thenReturn(new X500Principal("CN=duke, OU=JavaSoft, O=Sun Microsystems"))
                .thenReturn(new X500Principal("OU=JavaSoft, O=Sun Microsystems, C=US"));

        String rules = String.join(", ",
                "RULE:^CN=(.*),OU=ServiceUsers.*$/$1/L",
                "RULE:^CN=(.*),OU=(.*),O=(.*),L=(.*),ST=(.*),C=(.*)$/$1@$2/L",
                "RULE:^.*[Cc][Nn]=([a-zA-Z0-9.]*).*$/$1/U",
                "DEFAULT"
        );

        SslPrincipalMapper mapper = SslPrincipalMapper.fromRules(rules);
        DefaultKafkaPrincipalBuilder builder = new DefaultKafkaPrincipalBuilder(null, mapper);

        SslAuthenticationContext sslContext = new SslAuthenticationContext(session, InetAddress.getLocalHost(), SecurityProtocol.PLAINTEXT.name());

        KafkaPrincipal principal = builder.build(sslContext);
        assertEquals("duke", principal.getName());

        principal = builder.build(sslContext);
        assertEquals("duke@sme", principal.getName());

        principal = builder.build(sslContext);
        assertEquals("DUKE", principal.getName());

        principal = builder.build(sslContext);
        assertEquals("OU=JavaSoft,O=Sun Microsystems,C=US", principal.getName());

        builder.close();
        verify(session, times(4)).getPeerPrincipal();
    }

    @Test
    public void testPrincipalBuilderScram() throws Exception {
        SaslServer server = mock(SaslServer.class);

        EasyMock.expect(server.getMechanismName()).andReturn(ScramMechanism.SCRAM_SHA_256.mechanismName());
        EasyMock.expect(server.getAuthorizationID()).andReturn("foo");

        replayAll();

        DefaultKafkaPrincipalBuilder builder = new DefaultKafkaPrincipalBuilder(null, null);

        KafkaPrincipal principal = builder.build(new SaslAuthenticationContext(server,
                SecurityProtocol.SASL_PLAINTEXT, InetAddress.getLocalHost(), SecurityProtocol.SASL_PLAINTEXT.name()));
        assertEquals(KafkaPrincipal.USER_TYPE, principal.getPrincipalType());
        assertEquals("foo", principal.getName());

        builder.close();
        verifyAll();
    }

    @Test
    public void testPrincipalBuilderGssapi() throws Exception {
        SaslServer server = mock(SaslServer.class);
        KerberosShortNamer kerberosShortNamer = mock(KerberosShortNamer.class);

        EasyMock.expect(server.getMechanismName()).andReturn(SaslConfigs.GSSAPI_MECHANISM);
        EasyMock.expect(server.getAuthorizationID()).andReturn("foo/host@REALM.COM");
        EasyMock.expect(kerberosShortNamer.shortName(EasyMock.anyObject(KerberosName.class)))
                .andReturn("foo");

        replayAll();

        DefaultKafkaPrincipalBuilder builder = new DefaultKafkaPrincipalBuilder(kerberosShortNamer, null);

        KafkaPrincipal principal = builder.build(new SaslAuthenticationContext(server,
                SecurityProtocol.SASL_PLAINTEXT, InetAddress.getLocalHost(), SecurityProtocol.SASL_PLAINTEXT.name()));
        assertEquals(KafkaPrincipal.USER_TYPE, principal.getPrincipalType());
        assertEquals("foo", principal.getName());

        builder.close();
        verifyAll();
    }

    private static class DummyPrincipal implements Principal {
        private final String name;

        private DummyPrincipal(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

}
