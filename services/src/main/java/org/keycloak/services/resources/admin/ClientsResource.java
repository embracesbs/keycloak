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
package org.keycloak.services.resources.admin;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.Config;
import org.keycloak.authorization.admin.AuthorizationService;
import org.keycloak.common.Profile;
import org.keycloak.events.Errors;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.AdminClientRegisterContext;
import org.keycloak.services.clientpolicy.context.AdminClientRegisteredContext;
import org.keycloak.services.managers.ClientManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.utils.SearchQueryUtils;
import org.keycloak.validation.ValidationUtil;

import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import static java.lang.Boolean.TRUE;
import static org.keycloak.utils.StreamsUtil.paginatedStream;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import static java.lang.Boolean.TRUE;

/**
 * Base resource class for managing a realm's clients.
 *
 * @resource Clients
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ClientsResource {
    protected static final Logger logger = Logger.getLogger(ClientsResource.class);
    protected RealmModel realm;
    private AdminPermissionEvaluator auth;
    private AdminEventBuilder adminEvent;

    @Context
    protected KeycloakSession session;

    public ClientsResource(RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.realm = realm;
        this.auth = auth;
        this.adminEvent = adminEvent.resource(ResourceType.CLIENT);

    }

    /**
     * Get clients belonging to the realm
     * <p>
     * Returns a list of clients belonging to the realm
     *
     * @param clientId     filter by clientId
     * @param viewableOnly filter clients that cannot be viewed in full by admin
     * @param search       whether this is a search query or a getClientById query
     * @param firstResult  the first result
     * @param maxResults   the max results to return
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Stream<ClientRepresentation> getClients(@QueryParam("clientId") String clientId,
                                                 @QueryParam("viewableOnly") @DefaultValue("false") boolean viewableOnly,
                                                 @QueryParam("search") @DefaultValue("false") boolean search,
                                                 @QueryParam("q") String searchQuery,
                                                 @QueryParam("first") Integer firstResult,
                                                 @QueryParam("max") Integer maxResults) {
        auth.clients().requireList();

        boolean canView = auth.clients().canView();
        Stream<ClientModel> clientModels = Stream.empty();
        // TODO: probably new code is fine, but check with old changes to be sure
        if (searchQuery != null) {
            Map<String, String> attributes = SearchQueryUtils.getFields(searchQuery);
            clientModels = canView
                    ? realm.searchClientByAttributes(attributes, firstResult, maxResults)
                    : realm.searchClientByAttributes(attributes, -1, -1);
        } else if (clientId == null || clientId.trim().equals("")) {
            clientModels = canView
                    ? realm.getClientsStream(firstResult, maxResults)
                    : realm.getClientsStream();
        } else if (search) {
            clientModels = canView
                    ? realm.searchClientByClientIdStream(clientId, firstResult, maxResults)
                    : realm.searchClientByClientIdStream(clientId, -1, -1);
        } else {
            ClientModel client = realm.getClientByClientId(clientId);
            if (client != null) {
                clientModels = Stream.of(client);
            }
        }

        Stream<ClientRepresentation> s = clientModels
                .filter(c -> { try { c.getClientId(); return true; } catch (Exception ex) { return false; } } )
                .map(c -> {
                    ClientRepresentation representation = null;
                    if (canView || auth.clients().canView(c)) {
                        representation = ModelToRepresentation.toRepresentation(c, session);
                        representation.setAccess(auth.clients().getAccess(c));
                    } else if (!viewableOnly && auth.clients().canView(c)) {
                        representation = new ClientRepresentation();
                        representation.setId(c.getId());
                        representation.setClientId(c.getClientId());
                        representation.setDescription(c.getDescription());
                    }

                    return representation;
                })
                .filter(Objects::nonNull);

        if (!canView) {
            s = paginatedStream(s, firstResult, maxResults);
        }

        return s;
    }

    private AuthorizationService getAuthorizationService(ClientModel clientModel) {
        return new AuthorizationService(session, clientModel, auth, adminEvent);
    }

    /**
     * Create a new client
     * <p>
     * Client's client_id must be unique!
     *
     * @param rep
     * @return
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response createClient(final ClientRepresentation rep) {
        auth.clients().requireManage();

        try {
            session.clientPolicy().triggerOnEvent(new AdminClientRegisterContext(rep, auth.adminAuth()));

            ClientModel clientModel = ClientManager.createClient(session, realm, rep);

            ClientManager manager = new ClientManager(new RealmManager(session));

            if (TRUE.equals(rep.isServiceAccountsEnabled())) {
                UserModel serviceAccount = session.users().getServiceAccount(clientModel);

                if (serviceAccount == null) {
                    manager.enableServiceAccount(clientModel);
                }
            }

            adminEvent.operation(OperationType.CREATE).resourcePath(session.getContext().getUri(), clientModel.getId()).representation(rep).success();

            if (Profile.isFeatureEnabled(Profile.Feature.AUTHORIZATION) && TRUE.equals(rep.getAuthorizationServicesEnabled())) {
                AuthorizationService authorizationService = getAuthorizationService(clientModel);

                authorizationService.enable(true);

                ResourceServerRepresentation authorizationSettings = rep.getAuthorizationSettings();

                if (authorizationSettings != null) {
                    authorizationService.resourceServer().importSettings(authorizationSettings);
                }
            }
            
            // TODO: check this with old change
            // is client is multi tenant client in 'master' realm ... do the MT voodoo ...
            if (TRUE.equals(manager.isMultiTenantClientRepresentation(rep)) && realm.getName().equals(Config.getAdminRealm())) {
                boolean creationSuccess = manager.setupMultiTenantClientRegistrations(session, realm, clientModel, rep);
                if (!creationSuccess) {
                    session.getTransactionManager().setRollbackOnly();
                    throw new ErrorResponseException(Errors.INVALID_INPUT, "multi-tenant client instances registrations failed!", Response.Status.BAD_REQUEST);
                }
            }

            ValidationUtil.validateClient(session, clientModel, true, r -> {
                session.getTransactionManager().setRollbackOnly();
                throw new ErrorResponseException(
                        Errors.INVALID_INPUT,
                        r.getAllLocalizedErrorsAsString(AdminRoot.getMessages(session, realm, auth.adminAuth().getToken().getLocale())),
                        Response.Status.BAD_REQUEST);
            });

            session.clientPolicy().triggerOnEvent(new AdminClientRegisteredContext(clientModel, auth.adminAuth()));

            return Response.created(session.getContext().getUri().getAbsolutePathBuilder().path(clientModel.getId()).build()).build();
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Client " + rep.getClientId() + " already exists");
        } catch (ClientPolicyException cpe) {
            throw new ErrorResponseException(cpe.getError(), cpe.getErrorDetail(), Response.Status.BAD_REQUEST);
        }
    }

    /**
     * Base path for managing a specific client.
     *
     * @param id id of client (not client-id)
     * @return
     */
    @Path("{id}")
    public ClientResource getClient(final @PathParam("id") String id) {

        ClientModel clientModel = realm.getClientById(id);
        if (clientModel == null) {
            // we do this to make sure somebody can't phish ids
            if (auth.clients().canList()) throw new NotFoundException("Could not find client");
            else throw new ForbiddenException();
        }

        session.getContext().setClient(clientModel);

        ClientResource clientResource = new ClientResource(realm, auth, clientModel, session, adminEvent);
        ResteasyProviderFactory.getInstance().injectProperties(clientResource);
        return clientResource;
    }

    /**
     * Path for retrieval of all multi-tenant client
     * related client ids (non-master realm clients).
     *
     * @param clientId of client (not id)
     * @return list of realmName-clientId tuples
     */
    @GET
    @Path("/multitenant/{clientId}")
    @Produces(MediaType.APPLICATION_JSON)
    public List<RealmWithClientUidRepresentation> getMultiTenantClientIds(final @PathParam("clientId") String clientId) {

        // here we go:
        // 0. must have special realm role!
        // 1. check if current realm master
        // 2. check if client exists
        // 3. check if client is multi-tenant
        // 4. list all non-master realms
        // 5. foreach get client by clientId
        // 6. make a list and return

        // 0. must have special realm role!
        if (FALSE.equals(auth.clients().canListMultitenantClientIds())) {
            throw new ForbiddenException();
        }

        //try to resolve multitenant client
        // 1. check if client exists
        ClientModel clientModel = realm.getClientByClientId(clientId);
        if (clientModel == null) {
            // doing this to make sure somebody can't phish ids
            throw new NotFoundException("Could not find client");
        }

        // 2. check current realm 'master'
        // 3. check client is multi-tenant
        if (FALSE.equals(clientModel.getMultiTenant())
                || !realm.getName().equals(Config.getAdminRealm())) {
            throw new NotFoundException("Not a MultiTenant Client.");
        }

        List<RealmWithClientUidRepresentation> result = new ArrayList<>();

        // 4. list all non-master realms
        // 5. foreach get client by clientId
        // 6. make a list and return
        List<RealmModel> realms = session.realms().getRealms();

        for (RealmModel realmElement : realms) {
            String currentRealmName = realmElement.getName();

            // exclude 'master'
            if (currentRealmName.equals(Config.getAdminRealm()))
                continue;

            ClientModel realmClientFound = realmElement.getClientByClientId(clientId);
            if (realmClientFound == null)
                continue;

            result.add(RealmWithClientUidRepresentation
                    .asRepresentation(currentRealmName, realmClientFound.getId()));
        }

        return result;
    }

    public static class RealmWithClientUidRepresentation implements Serializable {
        private String realmName;
        private String clientGuid;

        private RealmWithClientUidRepresentation(String realmName, String clientGuid){
            this.realmName = realmName;
            this.clientGuid = clientGuid;
        }

        public static RealmWithClientUidRepresentation asRepresentation(String realmName, String clientUid){
            return new RealmWithClientUidRepresentation(realmName, clientUid);
        }

        public String getRealmName() {
            return realmName;
        }

        public void setRealmName(String realmName) {
            this.realmName = realmName;
        }

        public String getClientGuid() {
            return clientGuid;
        }

        public void setClientGuid(String clientGuid) {
            this.clientGuid = clientGuid;
        }
    }
}
