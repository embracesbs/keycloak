/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.models.jpa;

import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.protocol.saml.SamlConfigAttributes;

import javax.persistence.EntityManager;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.models.jpa.JpaRealmProviderFactory.PROVIDER_ID;
import static org.keycloak.models.jpa.JpaRealmProviderFactory.PROVIDER_PRIORITY;

public class JpaClientProviderFactory implements ClientProviderFactory {

    private Set<String> clientSearchableAttributes = null;

    private static final List<String> REQUIRED_SEARCHABLE_ATTRIBUTES = Arrays.asList(
            "saml_idp_initiated_sso_url_name",
            SamlConfigAttributes.SAML_ARTIFACT_BINDING_IDENTIFIER
    );

    private static final List<String> EMBRACE_SEARCHABLE_ATTRIBUTES = Arrays.asList(
            ClientModel.MULTI_TENANT
    );

    @Override
    public void init(Config.Scope config) {
        String[] searchableAttrsArr = config.getArray("searchableAttributes");
        if (searchableAttrsArr == null) {
            String s = System.getProperty("keycloak.client.searchableAttributes");
            searchableAttrsArr = s == null ? null : s.split("\\s*,\\s*");
        }
        List<String> SEARCHABLE_ATTRIBUTES_COMBINED =
                Stream.of(REQUIRED_SEARCHABLE_ATTRIBUTES, EMBRACE_SEARCHABLE_ATTRIBUTES)
                        .flatMap(Collection::stream)
                        .collect(Collectors.toList());

        HashSet<String> s = new HashSet<>(SEARCHABLE_ATTRIBUTES_COMBINED);
        if (searchableAttrsArr != null) {
            s.addAll(Arrays.asList(searchableAttrsArr));
        }
        clientSearchableAttributes = Collections.unmodifiableSet(s);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public ClientProvider create(KeycloakSession session) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new JpaRealmProvider(session, em, clientSearchableAttributes);
    }

    @Override
    public void close() {
    }

    @Override
    public int order() {
        return PROVIDER_PRIORITY;
    }

}
