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
package org.keycloak.services.resources;

import com.fasterxml.jackson.core.type.TypeReference;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Resteasy;
import org.keycloak.config.ConfigProviderFactory;
import org.keycloak.exportimport.ExportImportConfig;
import org.keycloak.exportimport.ExportImportManager;
import org.keycloak.exportimport.Strategy;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.dblock.DBLockManager;
import org.keycloak.models.dblock.DBLockProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.platform.Platform;
import org.keycloak.platform.PlatformProvider;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.error.KeycloakErrorHandler;
import org.keycloak.services.error.KcUnrecognizedPropertyExceptionHandler;
import org.keycloak.services.error.KeycloakMismatchedInputExceptionHandler;
import org.keycloak.services.filters.KeycloakSecurityHeadersFilter;
import org.keycloak.services.managers.ApplianceBootstrap;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.services.util.ObjectMapperResolver;
import org.keycloak.transaction.JtaTransactionManagerLookup;
import org.keycloak.util.JsonSerialization;

import jakarta.transaction.SystemException;
import jakarta.transaction.Transaction;
import jakarta.ws.rs.core.Application;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.ServiceLoader;
import java.util.Set;

import java.util.*;

import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.AdminRoles;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.ResourceServerStore;
import org.keycloak.constants.EmbraceMultiTenantConstants;
import org.keycloak.services.util.ResourceServerDefaultPermissionCreator;
import java.util.stream.Collectors;
import static java.lang.Boolean.TRUE;

import java.util.stream.Stream;
/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class KeycloakApplication extends Application {

    private static final Logger logger = Logger.getLogger(KeycloakApplication.class);

    protected final PlatformProvider platform = Platform.getPlatform();

    protected Set<Object> singletons = new HashSet<Object>();
    protected Set<Class<?>> classes = new HashSet<Class<?>>();

    private static KeycloakSessionFactory sessionFactory;

    public KeycloakApplication() {

        try {

            logger.debugv("PlatformProvider: {0}", platform.getClass().getName());
            logger.debugv("RestEasy provider: {0}", Resteasy.getProvider().getClass().getName());

            loadConfig();

            classes.add(RobotsResource.class);
            classes.add(RealmsResource.class);
            if (Profile.isFeatureEnabled(Profile.Feature.ADMIN_API)) {
                classes.add(AdminRoot.class);
            }
            classes.add(ThemeResource.class);

            if (Profile.isFeatureEnabled(Profile.Feature.JS_ADAPTER)) {
                classes.add(JsResource.class);
            }

            classes.add(KeycloakSecurityHeadersFilter.class);
            classes.add(KeycloakErrorHandler.class);
            classes.add(KcUnrecognizedPropertyExceptionHandler.class);
            classes.add(KeycloakMismatchedInputExceptionHandler.class);

            singletons.add(new ObjectMapperResolver());
            classes.add(WelcomeResource.class);

            if (Profile.isFeatureEnabled(Profile.Feature.MULTI_SITE)) {
                // If we are running in multi-site mode, we need to add a resource which to expose
                // an endpoint for the load balancer to gather information whether this site should receive requests or not.
                classes.add(LoadBalancerResource.class);
            }

            platform.onStartup(this::startup);
            platform.onShutdown(this::shutdown);

        } catch (Throwable t) {
            platform.exit(t);
        }

    }

    protected void startup() {
        CryptoIntegration.init(KeycloakApplication.class.getClassLoader());
        KeycloakApplication.sessionFactory = createSessionFactory();

        ExportImportManager[] exportImportManager = new ExportImportManager[1];

        KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {
            @Override
            public void run(KeycloakSession session) {
                DBLockManager dbLockManager = new DBLockManager(session);
                dbLockManager.checkForcedUnlock();
                DBLockProvider dbLock = dbLockManager.getDBLock();
                dbLock.waitForLock(DBLockProvider.Namespace.KEYCLOAK_BOOT);
                try {
                    exportImportManager[0] = bootstrap();
                } finally {
                    dbLock.releaseLock();
                }
            }
        });

        if (exportImportManager[0].isRunExport()) {
            exportImportManager[0].runExport();
        }

        sessionFactory.publish(new PostMigrationEvent(sessionFactory));
    }

    protected void shutdown() {
        if (sessionFactory != null)
            sessionFactory.close();
    }

    // Bootstrap master realm, import realms and create admin user.
    protected ExportImportManager bootstrap() {
        ExportImportManager[] exportImportManager = new ExportImportManager[1];

        logger.debug("bootstrap");
        KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {
            @Override
            public void run(KeycloakSession session) {
                // TODO what is the purpose of following piece of code? Leaving it as is for now.
                JtaTransactionManagerLookup lookup = (JtaTransactionManagerLookup) sessionFactory.getProviderFactory(JtaTransactionManagerLookup.class);
                if (lookup != null) {
                    if (lookup.getTransactionManager() != null) {
                        try {
                            Transaction transaction = lookup.getTransactionManager().getTransaction();
                            logger.debugv("bootstrap current transaction? {0}", transaction != null);
                            if (transaction != null) {
                                logger.debugv("bootstrap current transaction status? {0}", transaction.getStatus());
                            }
                        } catch (SystemException e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
                // TODO up here ^^

                ApplianceBootstrap applianceBootstrap = new ApplianceBootstrap(session);
                exportImportManager[0] = new ExportImportManager(session);

                boolean createMasterRealm = applianceBootstrap.isNewInstall();
                if (exportImportManager[0].isRunImport() && exportImportManager[0].isImportMasterIncluded()) {
                    createMasterRealm = false;
                }

                if (createMasterRealm) {
                    applianceBootstrap.createMasterRealm();
                }

                String runEmbraceMIgrationsStr = System.getProperty("runEmbraceMigrations");
                if(Boolean.parseBoolean(runEmbraceMIgrationsStr)) {
                    // once-run embrace data migration:
                    embraceMigration01(session);
                    embraceMigration02(session);
                    embraceMigration03(session);
                }
            }
        });

        if (exportImportManager[0].isRunImport()) {
            exportImportManager[0].runImport();
        } else {
            importRealms(exportImportManager[0]);
        }

        importAddUser();

        return exportImportManager[0];
    }

    protected void embraceMigration01(KeycloakSession session) {
        // custom migrations for patching the existing data
        logger.infov("Embrace data migration script 01 ...");
        logger.infov("01. Add QUERY_MULTITENANT_CLIENT_IDS System Role Migration");

        // check if master exists (first start!)
        RealmModel masterRealm = session.realms().getRealm(Config.getAdminRealm());
        if (null == masterRealm) return; //ths is first app start against empty DB

        // 01. QUERY_MULTITENANT_CLIENT_IDS Migration
        try {
            // add queryClientIdsRole to master admin app and make it admin role composite:
            ClientModel masterAdminApp = masterRealm.getClientByClientId(masterRealm.getName() + AdminRoles.APP_SUFFIX);

            // validate if we need to run the rest of the script:
            logger.infov("Checking if multi-tenancy related migration is already done...");
            RoleModel queryMtClientIdsRole = masterAdminApp.getRole(AdminRoles.QUERY_MULTITENANT_CLIENT_IDS);
            if (null != queryMtClientIdsRole) {
                logger.infov("Multi-tenancy related migration already done! Script run dismissed.");
                return; // custom migration already done
            }

            logger.infov("Multi-tenancy related migration - START!");
            RoleModel adminRole = masterRealm.getRole(AdminRoles.ADMIN);

            logger.infov("Multi-tenancy migration - Adding role {0} to masterApp!", AdminRoles.QUERY_MULTITENANT_CLIENT_IDS);
            String queryClientIds = AdminRoles.QUERY_MULTITENANT_CLIENT_IDS;
            RoleModel queryClientIdsRole = masterAdminApp.addRole(queryClientIds);
            queryClientIdsRole.setDescription("${role_" + queryClientIds + "}");

            logger.infov("Multi-tenancy migration - Adding role {0} to admin role composites!", AdminRoles.QUERY_MULTITENANT_CLIENT_IDS);
            adminRole.addCompositeRole(queryClientIdsRole);

            // search for multitenant clients
            logger.infov("Multi-tenancy migration - Searching for existing multi-tenant clients!");
            Map<String, String> attributes = Collections.singletonMap(ClientModel.MULTI_TENANT, TRUE.toString());
            List<ClientModel> multiTenantMasterClients = session.clients().searchClientsByAttributes(masterRealm, attributes, 0, 200).collect(Collectors.toList());

            if (multiTenantMasterClients == null || multiTenantMasterClients.size() == 0) {
                logger.infov("Multi-tenancy migration - None existing multitenant clients found!");
                return; // no multitenant clients found
            }

            // foreach existing mt-client
            multiTenantMasterClients.forEach(multiTenantClient -> {
                logger.infov("Multi-tenancy migration - Multi-tenant client found: {0}! Migrating....", multiTenantClient.getClientId());
                // find service account user for this mt-client
                UserModel saUser = session.users().getServiceAccount(multiTenantClient);
                // grant role to the Service Account user of this mt-client
                logger.infov("Multi-tenancy migration - Granting special role {0} to client {1}....", AdminRoles.QUERY_MULTITENANT_CLIENT_IDS, multiTenantClient.getClientId());
                saUser.grantRole(queryClientIdsRole);
                logger.infov("Multi-tenancy migration - Multi-tenant client {0} migration success....", multiTenantClient.getClientId());
            });

            logger.infov("Multi-tenancy related migration - SUCCESS!");
        } catch (Exception e) {
            logger.infov("Multi-tenancy related migration - Failed! :: {0}", e.getMessage());
            throw e;
        }
    }



    protected void embraceMigration02(KeycloakSession session) {
        logger.infov("Embrace data migration script 02 ...");
        logger.infov("02. Multi-tenant Clients Default Permissions Migration");

        // check if master exists (first start!)
        RealmModel masterRealm = session.realms().getRealm(Config.getAdminRealm());
        if (null == masterRealm) return; //ths is first app start against empty DB

        // 02. Multi-tenant Clients Default Permissions Migration
        try {
            // search for multitenant clients
            logger.infov("Multi-tenant clients default permissions migration - Searching for existing multitenant clients ...");
            Map<String, String> attributes = Collections.singletonMap(ClientModel.MULTI_TENANT, TRUE.toString());
            List<ClientModel> multiTenantMasterClients = session.clients().searchClientsByAttributes(masterRealm, attributes, 0, 200).collect(Collectors.toList());

            if (multiTenantMasterClients == null || multiTenantMasterClients.size() == 0) {
                logger.infov("Multi-tenant clients default permissions migration - None of existing multitenant clients found. Nothing to migrate!");
                return; // no multitenant clients found
            }

            // mt clients found!
            AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);

            // list all user realms
            List<RealmModel> realms = session.realms().getRealmsStream().collect(Collectors.toList());

            // foreach user realm, foreach mt-client instance
            for (RealmModel clientRealm : realms) {

                // exclude "master"
                if (clientRealm.getName().equals(Config.getAdminRealm()))
                    continue;

                logger.infov("Multi-tenant clients default permissions migration - Changing the scope to realm {0} ....", clientRealm.getName());

                // foreach existing mt-client
                multiTenantMasterClients.forEach(multiTenantClient -> {
                    logger.infov("Multi-tenant clients default permissions migration - Search for realm instance client named {0} (realm {1}) ....",
                            multiTenantClient.getClientId(), clientRealm.getName());

                    // find realm client instance (by clientId)
                    ClientModel realmClientInstance = clientRealm.getClientByClientId(multiTenantClient.getClientId());

                    if (realmClientInstance == null) {
                        logger.infov("Multi-tenant clients default permissions migration - No multitenant client instance with name {0} found (realm {1})!",
                                multiTenantClient.getClientId(), clientRealm.getName());
                        return;
                    }

                    logger.infov("Multi-tenant clients default permissions migration - Multi-tenant client client instance named {0} (realm {1}) found!",
                            multiTenantClient.getClientId(), clientRealm.getName());

                    // find resource-server entity for this client
                    ResourceServerStore resourceServerStore = authorization.getStoreFactory().getResourceServerStore();

                    ResourceServer existingResourceServer = resourceServerStore.findById(realmClientInstance.getId());

                    if (existingResourceServer == null) {
                        logger.infov("Multi-tenant clients default permissions migration - No existing Resource Server entity for Multi-tenant client instance with name {0} found in realm {1}!",
                                multiTenantClient.getClientId(), clientRealm.getName());
                        return;
                    }

                    // check if Default Permissions are missing:
                    String defaultPermissionPolicyName = "Default Permission";

                    PolicyStore policyStore = authorization.getStoreFactory().getPolicyStore();

                    // validate already existing:
                    Policy existingDefaultPermission = policyStore.findByName(existingResourceServer, defaultPermissionPolicyName);

                    if (existingDefaultPermission != null) {
                        logger.infov("Multi-tenant clients default permissions migration - Existing 'Default Permission' policy found for Multi-tenant client instance with name {0} in realm: {1}! No need for migration!",
                                multiTenantClient.getClientId(), clientRealm.getName());
                        return;
                    }

                    logger.infov("Multi-tenant clients default permissions migration - MIGRATION STARTING for Multi-tenant client instance with name {0} (realm: {1})!",
                            multiTenantClient.getClientId(), clientRealm.getName());

                    ResourceServerDefaultPermissionCreator resourceServerDefaultPermissionCreator
                            = new ResourceServerDefaultPermissionCreator(session, authorization, existingResourceServer);

                    resourceServerDefaultPermissionCreator.create(realmClientInstance);

                    logger.infov("Multi-tenant clients default permissions migration - ENDED for Multi-tenant client instance with name {0} in realm: {1}!",
                            multiTenantClient.getClientId(), clientRealm.getName());
                });
            }
            logger.infov("Multi-tenant clients default permissions migration - SUCCESS!");
        } catch (Exception e) {
            logger.infov("Multi-tenant clients default permissions migration - Failed! :: {0}", e.getMessage());
            throw e;
        }
    }

    protected void embraceMigration03(KeycloakSession session) {
        logger.infov("Embrace data migration script 03 ...");

        // check if master exists (first start!)
        RealmModel masterRealm = session.realms().getRealm(Config.getAdminRealm());
        if (null == masterRealm) return; //ths is first app start against empty DB => no migration needed

        // 03a. Multi-tenant Clients Specialized Client Scopes
        logger.infov("03a. Multi-tenant Clients Specialized Client Scopes Migration-A - add missing master scopes!");
        try {
            // a. For every client realm create specialized multi-tenant client scope:
            List<RealmModel> realms = session.realms().getRealmsStream().collect(Collectors.toList());

            // foreach user realm, foreach mt-client instance
            for (RealmModel clientRealm : realms) {

                // exclude "master"
                if (clientRealm.getName().equals(Config.getAdminRealm()))
                    continue;

                logger.infov("Multi-tenant clients specialized client scopes migration - Changing the scope to client realm {0} ....", clientRealm.getName());

                String realmRelatedScopeName = EmbraceMultiTenantConstants.MULTI_TENANT_SPECIFIC_CLIENT_SCOPE_PREFIX + clientRealm.getName();

                logger.infov("Multi-tenant clients specialized client scopes migration - Searching for master scope {0} ....", realmRelatedScopeName);

                Stream<ClientScopeModel> masterClientScopesCurrent = masterRealm.getClientScopesStream();
                if (masterClientScopesCurrent.map(ClientScopeModel::getName).collect(Collectors.toList()).contains(realmRelatedScopeName)) {
                    logger.infov("Multi-tenant clients specialized client scopes migration - realm specific client scope {0} found in {1} realm. Move on to another client realm ...", realmRelatedScopeName, clientRealm.getName());
                    continue;
                }

                logger.infov("Multi-tenant clients specialized client scopes migration - realm related master scope {0} not found. Creating!!", realmRelatedScopeName);

                ClientScopeModel newScope = RealmManager.setupMultiTenantClientSpecificClientScope(clientRealm, masterRealm);

                if (newScope != null) {
                    logger.infov("Multi-tenant clients specialized client scopes migration - realm related master scope {0} created successfully", realmRelatedScopeName);
                }
            }
            logger.infov("Multi-tenant clients specialized client scopes migration-a - SUCCESS!");
        } catch (Exception e) {
            logger.infov("Multi-tenant clients specialized client scopes migration-a - Failed! :: {0}", e.getMessage());
            throw e;
        }



        logger.infov("03b. Multi-tenant Clients Specialized Client Scopes Migration-B - update existing multi-tenant clients!");
        try {
            // b. search for multi-tenant clients and update they're optional client scopes
            logger.infov("Multi-tenant clients specialized client scopes migration - Searching for existing multi-tenant clients ...");
            List<ClientModel> multiTenantMasterClients = session.clients().searchClientsByAttributes(masterRealm, Collections.singletonMap(ClientModel.MULTI_TENANT, TRUE.toString()), 0, 200).collect(Collectors.toList());

            if (multiTenantMasterClients == null || multiTenantMasterClients.size() == 0) {
                logger.infov("Multi-tenant clients specialized client scopes migration - None of existing multi-tenant clients found. End migration!");
                return; // no multi-tenant clients found
            }

            // find all master mt-client system client scopes
            List<ClientScopeModel> ipuRealmScopes = KeycloakModelUtils.findClientScopesByNamePrefix(masterRealm, EmbraceMultiTenantConstants.MULTI_TENANT_SPECIFIC_CLIENT_SCOPE_PREFIX).collect(Collectors.toList());

            // foreach existing mt-client
            multiTenantMasterClients.forEach(multiTenantClient -> {
                logger.infov("Multi-tenant clients specialized client scopes migration - Adding optional client scopes to mt-client with name {0} ....", multiTenantClient.getClientId());

                // set client scopes
                ipuRealmScopes.forEach(ipuRealmScope -> {
                    multiTenantClient.addClientScope(ipuRealmScope, false);
                });

                logger.infov("Multi-tenant clients specialized client scopes migration - Done for Multi-tenant client with name {0}!", multiTenantClient.getClientId());
            });

            logger.infov("Multi-tenant clients specialized client scopes migration-b - SUCCESS!");
        } catch (Exception e) {
            logger.infov("Multi-tenant clients specialized client scopes migration-b - Failed! :: {0}", e.getMessage());
            throw e;
        }
    }

    protected void loadConfig() {

        ServiceLoader<ConfigProviderFactory> loader = ServiceLoader.load(ConfigProviderFactory.class, KeycloakApplication.class.getClassLoader());

        try {
            ConfigProviderFactory factory = loader.iterator().next();
            logger.debugv("ConfigProvider: {0}", factory.getClass().getName());
            Config.init(factory.create().orElseThrow(() -> new RuntimeException("Failed to load Keycloak configuration")));
        } catch (NoSuchElementException e) {
            throw new RuntimeException("No valid ConfigProvider found");
        }

    }

    protected KeycloakSessionFactory createSessionFactory() {
        DefaultKeycloakSessionFactory factory = new DefaultKeycloakSessionFactory();
        factory.init();
        return factory;
    }

    public static KeycloakSessionFactory getSessionFactory() {
        return sessionFactory;
    }

    @Override
    public Set<Class<?>> getClasses() {
        return classes;
    }

    @Override
    public Set<Object> getSingletons() {
        return singletons;
    }

    public void importRealms(ExportImportManager exportImportManager) {
        String dir = System.getProperty("keycloak.import");
        if (dir != null) {
            try {
                System.setProperty(ExportImportConfig.STRATEGY, Strategy.IGNORE_EXISTING.toString());
                exportImportManager.runImportAtStartup(dir);
            } catch (IOException cause) {
                throw new RuntimeException("Failed to import realms", cause);
            }
        }
    }

    public void importRealm(RealmRepresentation rep, String from) {
        boolean exists = false;
        try (KeycloakSession session = sessionFactory.create()) {
            session.getTransactionManager().begin();

            try {
                RealmManager manager = new RealmManager(session);

                if (rep.getId() != null && manager.getRealm(rep.getId()) != null) {
                    ServicesLogger.LOGGER.realmExists(rep.getRealm(), from);
                    exists = true;
                }

                if (manager.getRealmByName(rep.getRealm()) != null) {
                    ServicesLogger.LOGGER.realmExists(rep.getRealm(), from);
                    exists = true;
                }
                if (!exists) {
                    RealmModel realm = manager.importRealm(rep);
                    ServicesLogger.LOGGER.importedRealm(realm.getName(), from);
                }
            } catch (Throwable t) {
                session.getTransactionManager().setRollbackOnly();
                throw t;
            }
        } catch (Throwable t) {
            if (!exists) {
                ServicesLogger.LOGGER.unableToImportRealm(t, rep.getRealm(), from);
            }
        }
    }

    public void importAddUser() {
        String configDir = System.getProperty("jboss.server.config.dir");
        if (configDir != null) {
            File addUserFile = new File(configDir + File.separator + "keycloak-add-user.json");
            if (addUserFile.isFile()) {
                ServicesLogger.LOGGER.imprtingUsersFrom(addUserFile);

                List<RealmRepresentation> realms;
                try {
                    realms = JsonSerialization.readValue(new FileInputStream(addUserFile), new TypeReference<List<RealmRepresentation>>() {
                    });
                } catch (IOException e) {
                    ServicesLogger.LOGGER.failedToLoadUsers(e);
                    return;
                }

                for (RealmRepresentation realmRep : realms) {
                    for (UserRepresentation userRep : realmRep.getUsers()) {
                        try {
                            KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
                                RealmModel realm = session.realms().getRealmByName(realmRep.getRealm());

                                if (realm == null) {
                                    ServicesLogger.LOGGER.addUserFailedRealmNotFound(userRep.getUsername(), realmRep.getRealm());
                                }

                                UserProvider users = session.users();

                                if (users.getUserByUsername(realm, userRep.getUsername()) != null) {
                                    ServicesLogger.LOGGER.notCreatingExistingUser(userRep.getUsername());
                                } else {
                                    UserModel user = RepresentationToModel.createUser(session, realm, userRep);
                                    ServicesLogger.LOGGER.addUserSuccess(userRep.getUsername(), realmRep.getRealm());
                                }
                            });
                        } catch (ModelDuplicateException e) {
                            ServicesLogger.LOGGER.addUserFailedUserExists(userRep.getUsername(), realmRep.getRealm());
                        } catch (Throwable t) {
                            ServicesLogger.LOGGER.addUserFailed(t, userRep.getUsername(), realmRep.getRealm());
                        }
                    }
                }

                if (!addUserFile.delete()) {
                    ServicesLogger.LOGGER.failedToDeleteFile(addUserFile.getAbsolutePath());
                }
            }
        }
    }
}
