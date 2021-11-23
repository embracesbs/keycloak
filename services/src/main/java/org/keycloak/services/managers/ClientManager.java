/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.services.managers;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.ClientAuthenticator;
import org.keycloak.authentication.ClientAuthenticatorFactory;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.store.ResourceServerStore;
import org.keycloak.common.constants.ServiceAccountConstants;
import org.keycloak.common.util.Time;
import org.keycloak.constants.EmbraceMultiTenantConstants;
import org.keycloak.models.*;
import org.keycloak.models.session.UserSessionPersisterProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.UserSessionNoteMapper;
import org.keycloak.representations.adapters.config.BaseRealmConfig;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.keycloak.services.util.ResourceServerDefaultPermissionCreator;
import org.keycloak.sessions.AuthenticationSessionProvider;

import java.io.*;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ClientManager {
    private static final Logger logger = Logger.getLogger(ClientManager.class);
    public static final String multiTenantDescriptionSuffix = "[multi-tenant]";
    public static final String multiTenantInstanceDescriptionSuffix = "[multi-tenant instance]";
    public static final String resourceServerDescriptionSuffix = "[resource-server]";

    protected RealmManager realmManager;

    public ClientManager(RealmManager realmManager) {
        this.realmManager = realmManager;
    }

    public ClientManager() {
    }

    /**
     * Should not be called from an import.  This really expects that the client is created from the admin console.
     *
     * @param session
     * @param realm
     * @param rep
     * @param addDefaultRoles
     * @return
     */
    public static ClientModel createClient(KeycloakSession session, RealmModel realm, ClientRepresentation rep, boolean addDefaultRoles) {
        ClientModel client = RepresentationToModel.createClient(session, realm, rep, addDefaultRoles);

        if (rep.getProtocol() != null) {
            LoginProtocolFactory providerFactory = (LoginProtocolFactory) session.getKeycloakSessionFactory().getProviderFactory(LoginProtocol.class, rep.getProtocol());
            providerFactory.setupClientDefaults(rep, client);
        }

        // remove default mappers if there is a template
        if (rep.getProtocolMappers() == null && rep.getClientTemplate() != null) {
            Set<ProtocolMapperModel> mappers = client.getProtocolMappers();
            for (ProtocolMapperModel mapper : mappers) client.removeProtocolMapper(mapper);
        }
        return client;

    }

    // MULTI_TENANT_CLIENT =>
    //   'public=false',
    //   'serviceAccountEnabled=true',
    //   has attribute 'multi.tenant.client'=true,
    //   has attribute "multi.tenant.service.account.roles"
    public boolean setupMultiTenantClientRegistrations(KeycloakSession session, RealmModel adminRealm, ClientModel mtClient, ClientRepresentation clientRepresentation) {

        // find service account user for this mt-client
        UserModel mtClientServiceAccount = realmManager.getSession().users().getServiceAccount(mtClient);

        String[] serviceAccountRoles = mtClient.getMultiTenantServiceAccountRoles(clientRepresentation.getAttributes());
        boolean isResourceServerClient = ContainsResourceServerRole(serviceAccountRoles);

        List<RealmModel> realms = session.realms().getRealms();

        for (RealmModel realmElement : realms) {

            // exclude 'master'
            if (realmElement.getName().equals(Config.getAdminRealm()))
                continue;

            // create copy clients in realm by deep cloning the rep object
            ClientRepresentation realmClientRep = deepCopy(clientRepresentation);
            realmClientRep.setId(null);
            realmClientRep.setProtocolMappers(null);
            realmClientRep.setDefaultClientScopes(null);
            realmClientRep.setOptionalClientScopes(null);
            realmClientRep.setServiceAccountsEnabled(true);

            realmClientRep.setDescription(String.format("%s %s", clientRepresentation.getDescription(), multiTenantInstanceDescriptionSuffix));

            ClientModel realmInstanceClient = createClient(session, realmElement, realmClientRep, true);

            // create mandatory resource server service account:
            UserModel serviceAccount = session.users().getServiceAccount(realmInstanceClient);

            if (serviceAccount == null) {
                enableServiceAccount(realmInstanceClient);
            }

            // determine if Authorization Service needs to be enabled!
            // this effectively means that the client we are creating should be a Resource Server!
            if (isResourceServerClient) {
                realmClientRep.setAuthorizationServicesEnabled(TRUE);
                realmInstanceClient.setDescription(String.format("%s %s", realmClientRep.getDescription(), resourceServerDescriptionSuffix));
            }

            if (TRUE.equals(realmClientRep.getAuthorizationServicesEnabled())) {
                AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);

                // =>  resource server!
                ResourceServer resourceServer = RepresentationToModel.createResourceServer(realmInstanceClient, session, true);

                ResourceServerDefaultPermissionCreator resourceServerDefaultPermissionCreator
                        = new ResourceServerDefaultPermissionCreator(session, authorization, resourceServer);

                resourceServerDefaultPermissionCreator.create(realmInstanceClient);

                ResourceServerRepresentation authorizationSettings = realmClientRep.getAuthorizationSettings();

                if (authorizationSettings != null) {
                    realmClientRep.setClientId(realmInstanceClient.getId());
                    RepresentationToModel.toModel(authorizationSettings, authorization);
                }
            }

            // find master admin apps by name "{realmName}-realm"
            String masterAdminAppName = String.format("%s-realm", realmElement.getName());
            ClientModel masterAdminApp = adminRealm.getClientByClientId(masterAdminAppName);

            for (String roleName : serviceAccountRoles) {
                // find the appropriate role from master admin app
                RoleModel foundRole = masterAdminApp.getRole(roleName);

                if (foundRole == null) {
                    //log not found role!
                    logger.errorf("multi-tenant client service account -> role with name '%s' not found!", roleName);
                    continue;
                }
                // and role to the Service Account user of the master mt-client
                mtClientServiceAccount.grantRole(foundRole);
            }

        }

        // find master admin apps by name "master-realm"
        String masterRealmAppName = adminRealm.getName() + AdminRoles.APP_SUFFIX;
        ClientModel masterRealmApp = adminRealm.getClientByClientId(masterRealmAppName);

        // find the specialized role "query-multirealm-client-ids" from master admin app
        RoleModel foundRole = masterRealmApp.getRole(AdminRoles.QUERY_MULTITENANT_CLIENT_IDS);

        if (foundRole == null) {
            logger.errorf("multi-tenant client service account -> role with name '%s' not found!", AdminRoles.QUERY_MULTITENANT_CLIENT_IDS);
            return FALSE;
        }

        // and role to the Service Account user of the master mt-client
        mtClientServiceAccount.grantRole(foundRole);

        // scoped jwt roles support
        // in master realm should have set client scopes for each realm 'identity-provider-user-[realm_name]'
        // collect the all specialized client-scope by prefix and add them as optional scope to mt-client
        List<ClientScopeModel> ipuRealmScopes = KeycloakModelUtils.findClientScopesByNamePrefix(adminRealm, EmbraceMultiTenantConstants.MULTI_TENANT_SPECIFIC_CLIENT_SCOPE_PREFIX);
        for (ClientScopeModel ipuRealmScope : ipuRealmScopes)
        {
            mtClient.addClientScope(ipuRealmScope, false);
        }

        // update description on mt-client create
        mtClient.setDescription((clientRepresentation.getDescription() == null ? "" : clientRepresentation.getDescription() + " ") + multiTenantDescriptionSuffix);
        return TRUE;
    }

    public boolean updateMultiTenantClientRegistrations(KeycloakSession session, RealmModel adminRealm, ClientModel mtClientCurrent, ClientRepresentation updateClientRepresentation) {

        // find service account user for this mt-client
        UserModel mtClientServiceAccount = realmManager.getSession().users().getServiceAccount(mtClientCurrent);

        String[] serviceAccountRoles = mtClientCurrent.getMultiTenantServiceAccountRoles(updateClientRepresentation.getAttributes());
        boolean isResourceServerClient = ContainsResourceServerRole(serviceAccountRoles);

        boolean isClientIdUpdateCase = !updateClientRepresentation.getClientId().equalsIgnoreCase(mtClientCurrent.getClientId());
        boolean isNameUpdateCase = !updateClientRepresentation.getName().equalsIgnoreCase(mtClientCurrent.getName());

        if (isResourceServerClient) {
            // some updates to the master instance client?
        }

        List<RealmModel> realms = session.realms().getRealms();

        for (RealmModel realmElement : realms.stream()
                .filter(realmElement -> !realmElement.getName().equals(Config.getAdminRealm())) // filter-out 'master'
                .collect(Collectors.toList()))
        {
            // get current realm mt-client instance
            ClientModel realmMtClient = session.clientStorageManager().getClientByClientId(mtClientCurrent.getClientId(), realmElement);

            if (realmMtClient == null) {
                // someone deleted instance mt client manually?!
                logger.warnf("Instance multi-tenant client [%s] couldn't be found in realm [%s]! ", mtClientCurrent.getClientId(), realmElement.getName());
                continue;
            }

            // create updated client representation by deep cloning the rep object
            ClientRepresentation realmClientRep = deepCopy(updateClientRepresentation);
            realmClientRep.setId(realmMtClient.getId());

            // update name
            if (isClientIdUpdateCase) {
                realmMtClient.setClientId(realmClientRep.getClientId());
            }

            if (isNameUpdateCase) {
                realmMtClient.setName(realmClientRep.getName());
            }

            // update description in instance client if needed
            String repDescription = updateClientRepresentation.getDescription();
            if (repDescription == null || repDescription.isEmpty()) {
                repDescription = multiTenantInstanceDescriptionSuffix;
            } else{
                repDescription = repDescription.contains(multiTenantInstanceDescriptionSuffix) ? repDescription : String.format("%s %s", repDescription, multiTenantInstanceDescriptionSuffix);
            }
            realmMtClient.setDescription(repDescription);

            // update attributes (inline)!
            for (Map.Entry<String, String> entry : RepresentationToModel.removeEmptyString(realmClientRep.getAttributes()).entrySet()) {
                realmMtClient.setAttribute(entry.getKey(), entry.getValue());
            }

            // determine if Authorization Service needs to be enabled!
            // this effectively means that the mt client we are updating is becoming a Resource Server!
            if (isResourceServerClient) {
                realmClientRep.setAuthorizationServicesEnabled(TRUE);
            }

            if (TRUE.equals(realmClientRep.getAuthorizationServicesEnabled())) {

                AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
                ResourceServerStore resourceServerStore = authorization.getStoreFactory().getResourceServerStore();

                ResourceServer resourceServerExisting = resourceServerStore.findById(realmMtClient.getId());

                if (resourceServerExisting == null) { // if not null, already a resource-server instance!

                    // =>  adding resource server capabilities !
                    ResourceServer resourceServer = RepresentationToModel.createResourceServer(realmMtClient, session, true);

                    ResourceServerDefaultPermissionCreator resourceServerDefaultPermissionCreator
                            = new ResourceServerDefaultPermissionCreator(session, authorization, resourceServer);

                    resourceServerDefaultPermissionCreator.create(realmMtClient);

                    ResourceServerRepresentation authorizationSettings = realmClientRep.getAuthorizationSettings();

                    if (authorizationSettings != null) {
                        realmClientRep.setClientId(realmMtClient.getId());
                        RepresentationToModel.toModel(authorizationSettings, authorization);
                    }
                }

                // update description
                realmMtClient.setDescription(String.format("%s %s", repDescription, resourceServerDescriptionSuffix));

            }

            // find realm admin apps by name "{realmName}-realm"
            String realmAdminAppName = String.format("%s-realm", realmElement.getName());
            ClientModel realmAdminApp = adminRealm.getClientByClientId(realmAdminAppName);

            // first clear all existing roles and then add from current rep.
            Set<RoleModel> currentRoleMappings = mtClientServiceAccount.getClientRoleMappings(realmAdminApp);
            for (RoleModel current : currentRoleMappings)
                mtClientServiceAccount.deleteRoleMapping(current);

            for (String roleName : serviceAccountRoles) {
                // find the appropriate role from master admin app
                RoleModel foundRole = realmAdminApp.getRole(roleName);

                if (foundRole == null) {
                    //log not found role!
                    logger.errorf("multi-tenant client service account -> role with name '%s' not found!", roleName);
                    continue;
                }
                // and role to the Service Account user of the master mt-client
                mtClientServiceAccount.grantRole(foundRole);
            }
        }

        // find master admin apps by name "master-realm"
        String masterRealmAppName = String.format("%s%s", adminRealm.getName(), AdminRoles.APP_SUFFIX);
        ClientModel masterRealmApp = adminRealm.getClientByClientId(masterRealmAppName);

        // find the specialized role "query-multirealm-client-ids" from master admin app
        RoleModel foundRole = masterRealmApp.getRole(AdminRoles.QUERY_MULTITENANT_CLIENT_IDS);

        if (foundRole == null) {
            logger.errorf("multi-tenant client service account -> role with name '%s' not found!", AdminRoles.QUERY_MULTITENANT_CLIENT_IDS);
            return FALSE;
        }

        // and role to the Service Account user of the master mt-client
        mtClientServiceAccount.grantRole(foundRole);

        // scoped jwt roles support
        // in master realm should have set client scopes for each realm 'identity-provider-user-[realm_name]'
        // collect the all specialized client-scope by prefix and add them as optional scope to mt-client
        List<ClientScopeModel> ipuRealmScopes = KeycloakModelUtils.findClientScopesByNamePrefix(adminRealm, EmbraceMultiTenantConstants.MULTI_TENANT_SPECIFIC_CLIENT_SCOPE_PREFIX);
        for (ClientScopeModel ipuRealmScope : ipuRealmScopes)
        {
            mtClientCurrent.addClientScope(ipuRealmScope, false);
        }

        // update description in representation if needed
        String repDescription = updateClientRepresentation.getDescription();
        if (repDescription == null || repDescription.isEmpty()) {
            repDescription = multiTenantDescriptionSuffix;
        } else{
            repDescription = repDescription.contains(multiTenantDescriptionSuffix) ? repDescription : String.format("%s %s", repDescription, multiTenantDescriptionSuffix);
        }
        updateClientRepresentation.setDescription(repDescription);

        return TRUE;
    }

    public boolean removeClient(RealmModel realm, ClientModel client) {
        if (realm.removeClient(client.getId())) {
            UserSessionProvider sessions = realmManager.getSession().sessions();
            if (sessions != null) {
                sessions.onClientRemoved(realm, client);
            }

            UserSessionPersisterProvider sessionsPersister = realmManager.getSession().getProvider(UserSessionPersisterProvider.class);
            if (sessionsPersister != null) {
                sessionsPersister.onClientRemoved(realm, client);
            }

            AuthenticationSessionProvider authSessions = realmManager.getSession().authenticationSessions();
            if (authSessions != null) {
                authSessions.onClientRemoved(realm, client);
            }

            UserModel serviceAccountUser = realmManager.getSession().users().getServiceAccount(client);
            if (serviceAccountUser != null) {
                new UserManager(realmManager.getSession()).removeUser(realm, serviceAccountUser);
            }

            return true;
        } else {
            return false;
        }
    }

    public Set<String> validateRegisteredNodes(ClientModel client) {
        Map<String, Integer> registeredNodes = client.getRegisteredNodes();
        if (registeredNodes == null || registeredNodes.isEmpty()) {
            return Collections.emptySet();
        }
            
        int currentTime = Time.currentTime();

        Set<String> validatedNodes = new TreeSet<>();
        if (client.getNodeReRegistrationTimeout() > 0) {
            List<String> toRemove = new LinkedList<>();
            for (Map.Entry<String, Integer> entry : registeredNodes.entrySet()) {
                Integer lastReRegistration = entry.getValue();
                if (lastReRegistration + client.getNodeReRegistrationTimeout() < currentTime) {
                    toRemove.add(entry.getKey());
                } else {
                    validatedNodes.add(entry.getKey());
                }
            }

            // Remove time-outed nodes
            for (String node : toRemove) {
                client.unregisterNode(node);
            }
        } else {
            // Periodic node reRegistration is disabled, so allow all nodes
            validatedNodes.addAll(registeredNodes.keySet());
        }

        return validatedNodes;
    }

    public void enableServiceAccount(ClientModel client) {
        client.setServiceAccountsEnabled(true);

        // Add dedicated user for this service account
        if (realmManager.getSession().users().getServiceAccount(client) == null) {
            String username = ServiceAccountConstants.SERVICE_ACCOUNT_USER_PREFIX + client.getClientId();
            logger.debugf("Creating service account user '%s'", username);

            // Don't use federation for service account user
            UserModel user = realmManager.getSession().userLocalStorage().addUser(client.getRealm(), username);
            user.setEnabled(true);
            user.setServiceAccountClientLink(client.getId());
        }

        // Add protocol mappers to retrieve clientId in access token
        if (client.getProtocolMapperByName(OIDCLoginProtocol.LOGIN_PROTOCOL, ServiceAccountConstants.CLIENT_ID_PROTOCOL_MAPPER) == null) {
            logger.debugf("Creating service account protocol mapper '%s' for client '%s'", ServiceAccountConstants.CLIENT_ID_PROTOCOL_MAPPER, client.getClientId());
            ProtocolMapperModel protocolMapper = UserSessionNoteMapper.createClaimMapper(ServiceAccountConstants.CLIENT_ID_PROTOCOL_MAPPER,
                    ServiceAccountConstants.CLIENT_ID,
                    ServiceAccountConstants.CLIENT_ID, "String",
                    true, true);
            client.addProtocolMapper(protocolMapper);
        }

        // Add protocol mappers to retrieve hostname and IP address of client in access token
        if (client.getProtocolMapperByName(OIDCLoginProtocol.LOGIN_PROTOCOL, ServiceAccountConstants.CLIENT_HOST_PROTOCOL_MAPPER) == null) {
            logger.debugf("Creating service account protocol mapper '%s' for client '%s'", ServiceAccountConstants.CLIENT_HOST_PROTOCOL_MAPPER, client.getClientId());
            ProtocolMapperModel protocolMapper = UserSessionNoteMapper.createClaimMapper(ServiceAccountConstants.CLIENT_HOST_PROTOCOL_MAPPER,
                    ServiceAccountConstants.CLIENT_HOST,
                    ServiceAccountConstants.CLIENT_HOST, "String",
                    true, true);
            client.addProtocolMapper(protocolMapper);
        }

        if (client.getProtocolMapperByName(OIDCLoginProtocol.LOGIN_PROTOCOL, ServiceAccountConstants.CLIENT_ADDRESS_PROTOCOL_MAPPER) == null) {
            logger.debugf("Creating service account protocol mapper '%s' for client '%s'", ServiceAccountConstants.CLIENT_ADDRESS_PROTOCOL_MAPPER, client.getClientId());
            ProtocolMapperModel protocolMapper = UserSessionNoteMapper.createClaimMapper(ServiceAccountConstants.CLIENT_ADDRESS_PROTOCOL_MAPPER,
                    ServiceAccountConstants.CLIENT_ADDRESS,
                    ServiceAccountConstants.CLIENT_ADDRESS, "String",
                    true, true);
            client.addProtocolMapper(protocolMapper);
        }
    }

    public void clientIdChanged(ClientModel client, String newClientId) {
        logger.debugf("Updating clientId from '%s' to '%s'", client.getClientId(), newClientId);

        UserModel serviceAccountUser = realmManager.getSession().users().getServiceAccount(client);
        if (serviceAccountUser != null) {
            String username = ServiceAccountConstants.SERVICE_ACCOUNT_USER_PREFIX + newClientId;
            serviceAccountUser.setUsername(username);
        }
    }

    /** Makes a deep copy of any Serializable object that is passed.  **/
    @SuppressWarnings("unchecked")
    public static <T extends Serializable> T deepCopy(T serializable) {
        if (serializable == null) return null;
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(serializable);
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            return (T) objectInputStream.readObject();
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to deepCopy the client object!", e);
        }
    }


    @JsonPropertyOrder({"realm", "realm-public-key", "bearer-only", "auth-server-url", "ssl-required",
            "resource", "public-client", "verify-token-audience", "credentials",
            "use-resource-role-mappings"})
    public static class InstallationAdapterConfig extends BaseRealmConfig {
        @JsonProperty("resource")
        protected String resource;
        @JsonProperty("use-resource-role-mappings")
        protected Boolean useResourceRoleMappings;
        @JsonProperty("bearer-only")
        protected Boolean bearerOnly;
        @JsonProperty("public-client")
        protected Boolean publicClient;
        @JsonProperty("credentials")
        protected Map<String, Object> credentials;
        @JsonProperty("verify-token-audience")
        protected Boolean verifyTokenAudience;
        @JsonProperty("policy-enforcer")
        protected PolicyEnforcerConfig enforcerConfig;

        public Boolean isUseResourceRoleMappings() {
            return useResourceRoleMappings;
        }

        public void setUseResourceRoleMappings(Boolean useResourceRoleMappings) {
            this.useResourceRoleMappings = useResourceRoleMappings;
        }

        public String getResource() {
            return resource;
        }

        public void setResource(String resource) {
            this.resource = resource;
        }

        public Map<String, Object> getCredentials() {
            return credentials;
        }

        public void setCredentials(Map<String, Object> credentials) {
            this.credentials = credentials;
        }

        public Boolean getVerifyTokenAudience() {
            return verifyTokenAudience;
        }

        public void setVerifyTokenAudience(Boolean verifyTokenAudience) {
            this.verifyTokenAudience = verifyTokenAudience;
        }

        public Boolean getPublicClient() {
            return publicClient;
        }

        public void setPublicClient(Boolean publicClient) {
            this.publicClient = publicClient;
        }

        public Boolean getBearerOnly() {
            return bearerOnly;
        }

        public void setBearerOnly(Boolean bearerOnly) {
            this.bearerOnly = bearerOnly;
        }

        public PolicyEnforcerConfig getEnforcerConfig() {
            return this.enforcerConfig;
        }

        public void setEnforcerConfig(PolicyEnforcerConfig enforcerConfig) {
            this.enforcerConfig = enforcerConfig;
        }
    }


    public InstallationAdapterConfig toInstallationRepresentation(RealmModel realmModel, ClientModel clientModel, URI baseUri) {
        InstallationAdapterConfig rep = new InstallationAdapterConfig();
        rep.setAuthServerUrl(baseUri.toString());
        rep.setRealm(realmModel.getName());
        rep.setSslRequired(realmModel.getSslRequired().name().toLowerCase());

        if (clientModel.isPublicClient() && !clientModel.isBearerOnly()) rep.setPublicClient(true);
        if (clientModel.isBearerOnly()) rep.setBearerOnly(true);
        if (clientModel.getRoles().size() > 0) rep.setUseResourceRoleMappings(true);

        rep.setResource(clientModel.getClientId());

        if (showClientCredentialsAdapterConfig(clientModel)) {
            Map<String, Object> adapterConfig = getClientCredentialsAdapterConfig(clientModel);
            rep.setCredentials(adapterConfig);
        }

        return rep;
    }

    public String toJBossSubsystemConfig(RealmModel realmModel, ClientModel clientModel, URI baseUri) {
        StringBuffer buffer = new StringBuffer();
        buffer.append("<secure-deployment name=\"WAR MODULE NAME.war\">\n");
        buffer.append("    <realm>").append(realmModel.getName()).append("</realm>\n");
        buffer.append("    <auth-server-url>").append(baseUri.toString()).append("</auth-server-url>\n");
        if (clientModel.isBearerOnly()){
            buffer.append("    <bearer-only>true</bearer-only>\n");

        } else if (clientModel.isPublicClient()) {
            buffer.append("    <public-client>true</public-client>\n");
        }
        buffer.append("    <ssl-required>").append(realmModel.getSslRequired().name()).append("</ssl-required>\n");
        buffer.append("    <resource>").append(clientModel.getClientId()).append("</resource>\n");
        String cred = clientModel.getSecret();
        if (showClientCredentialsAdapterConfig(clientModel)) {
            Map<String, Object> adapterConfig = getClientCredentialsAdapterConfig(clientModel);
            for (Map.Entry<String, Object> entry : adapterConfig.entrySet()) {
                buffer.append("    <credential name=\"" + entry.getKey() + "\">");

                Object value = entry.getValue();
                if (value instanceof Map) {
                    buffer.append("\n");
                    Map<String, Object> asMap = (Map<String, Object>) value;
                    for (Map.Entry<String, Object> credEntry : asMap.entrySet()) {
                        buffer.append("        <" + credEntry.getKey() + ">" + credEntry.getValue().toString() + "</" + credEntry.getKey() + ">\n");
                    }
                    buffer.append("    </credential>\n");
                } else {
                    buffer.append(value.toString()).append("</credential>\n");
                }
            }
        }
        if (clientModel.getRoles().size() > 0) {
            buffer.append("    <use-resource-role-mappings>true</use-resource-role-mappings>\n");
        }
        buffer.append("</secure-deployment>\n");
        return buffer.toString();
    }

    private boolean ContainsResourceServerRole(String[] serviceAccountRoles) {
        return Arrays.stream(serviceAccountRoles).anyMatch(r -> r.contains("-authorization"));
    }

    private boolean showClientCredentialsAdapterConfig(ClientModel client) {
        if (client.isPublicClient()) {
            return false;
        }

        if (client.isBearerOnly() && client.getNodeReRegistrationTimeout() <= 0) {
            return false;
        }

        return true;
    }

    private Map<String, Object> getClientCredentialsAdapterConfig(ClientModel client) {
        String clientAuthenticator = client.getClientAuthenticatorType();
        ClientAuthenticatorFactory authenticator = (ClientAuthenticatorFactory) realmManager.getSession().getKeycloakSessionFactory().getProviderFactory(ClientAuthenticator.class, clientAuthenticator);
        return authenticator.getAdapterConfiguration(client);
    }

    public Boolean isMultiTenantClientRepresentation(ClientRepresentation clientRep) {
        Map<String, String> attributes = clientRep.getAttributes();
        if (attributes != null && attributes.containsKey(ClientModel.MULTI_TENANT)) {
            return Boolean.parseBoolean(attributes.get(ClientModel.MULTI_TENANT));
        }
        return Boolean.FALSE;
    }

}
