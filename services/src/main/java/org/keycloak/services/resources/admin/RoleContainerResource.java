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

import org.apache.commons.lang.ArrayUtils;
import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import javax.ws.rs.NotFoundException;

import org.keycloak.Config;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.ManagementPermissionReference;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.AdminPermissionManagement;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import sun.security.util.ArrayUtil;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.models.RoleModel.READ_ONLY_ROLE_ATTRIBUTE;
import static org.keycloak.models.RoleModel.READ_ONLY_ROLE_REALMS_ATTRIBUTE;

/**
 * @resource Roles
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class RoleContainerResource extends RoleResource {
    protected static final Logger logger = Logger.getLogger(RoleContainerResource.class);
    private final RealmModel realm;
    protected AdminPermissionEvaluator auth;

    protected RoleContainerModel roleContainer;
    private AdminEventBuilder adminEvent;
    private UriInfo uriInfo;
    private KeycloakSession session;

    public RoleContainerResource(KeycloakSession session, UriInfo uriInfo, RealmModel realm,
                                 AdminPermissionEvaluator auth, RoleContainerModel roleContainer, AdminEventBuilder adminEvent) {
        super(realm);
        this.uriInfo = uriInfo;
        this.realm = realm;
        this.auth = auth;
        this.roleContainer = roleContainer;
        this.adminEvent = adminEvent;
        this.session = session;
    }

    /**
     * Get all roles for the realm or client
     *
     * @return
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<RoleRepresentation> getRoles(@QueryParam("search") @DefaultValue("") String search,
                                             @QueryParam("first") Integer firstResult,
                                             @QueryParam("max") Integer maxResults,
                                             @QueryParam("briefRepresentation") @DefaultValue("true") boolean briefRepresentation) {
        auth.roles().requireList(roleContainer);

        Set<RoleModel> roleModels = new HashSet<RoleModel>();

        if(search != null && search.trim().length() > 0) {
            roleModels = roleContainer.searchForRoles(search, firstResult, maxResults);
        } else if (!Objects.isNull(firstResult) && !Objects.isNull(maxResults)) {
            roleModels = roleContainer.getRoles(firstResult, maxResults);
        } else {
            roleModels = roleContainer.getRoles();
        }

        List<RoleRepresentation> roles = new ArrayList<RoleRepresentation>();
        for (RoleModel roleModel : roleModels) {
            if(briefRepresentation) {
                roles.add(ModelToRepresentation.toBriefRepresentation(roleModel));  
            } else {
                roles.add(ModelToRepresentation.toRepresentation(roleModel));               
            }
        }
        return roles;
    }

    /**
     * Create a new role for the realm or client
     *
     * @param rep
     * @return
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response createRole(final RoleRepresentation rep) {
        auth.roles().requireManage(roleContainer);

        if (rep.getName() == null) {
            throw new BadRequestException();
        }

        try {
            RoleModel role = roleContainer.addRole(rep.getName());
            role.setDescription(rep.getDescription());

            rep.setId(role.getId());

            if (role.isClientRole()) {
                adminEvent.resource(ResourceType.CLIENT_ROLE);
            } else {
                adminEvent.resource(ResourceType.REALM_ROLE);
            }

            // readonly-role related registrations
            if (!role.isClientRole() && isReadOnly(rep)) {
                setupReadonlyRoleRegistrations(role, rep);
            }

            adminEvent.operation(OperationType.CREATE).resourcePath(uriInfo, role.getName()).representation(rep).success();

            return Response.created(uriInfo.getAbsolutePathBuilder().path(role.getName()).build()).build();
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Role with name " + rep.getName() + " already exists");
        }
    }

    private void setupReadonlyRoleRegistrations(RoleModel role, RoleRepresentation rep) {
        RealmModel adminRealm = session.realms().getRealm(Config.getAdminRealm());

        List<RealmModel> allRealms = session.realms().getRealms();

        String[] viewRoles = Arrays.stream(AdminRoles.ALL_REALM_ROLES)
                .filter(r -> r.startsWith("view-"))
                .toArray(String[]::new);

        String[] readOnlyRoles = Stream.of(viewRoles, AdminRoles.ALL_QUERY_ROLES)
                .flatMap(Stream::of)
                .toArray(String[]::new);

        String[] explicitRealmsFilter = getReadOnlyRoleRealms(rep);
        //boolean doFilter = explicitRealmsFilter.length > 0;
        boolean doFilter = Boolean.FALSE; //disabling realm filter-out functionality!

        for (RealmModel realmElement : allRealms) {
            // exclude 'master'
            if (realmElement.getName().equals(Config.getAdminRealm()))
                continue;

            // filter out if filter provided
            if (doFilter && Arrays.stream(explicitRealmsFilter).noneMatch(r -> r.equals(realmElement.getName()))) {
                // filter-out this realm !
                continue;
            }

            // find master admin apps by name "{realmName}-realm"
            String masterAdminAppName = realmElement.getName() + "-realm";
            ClientModel masterAdminApp = adminRealm.getClientByClientId(masterAdminAppName);

            for (String roleName : readOnlyRoles) {
                // find the appropriate role from master admin app
                RoleModel foundRole = masterAdminApp.getRole(roleName);

                if (foundRole == null) {
                    logger.errorf("read-only role registration -> master app role with name '%s' not found in app '%s'!", roleName, masterAdminAppName);
                    continue;
                }

                // and composite to the readonly role
                role.addCompositeRole(foundRole);
            }
        }
    }

    private boolean isReadOnly(RoleRepresentation rep) {
        Map<String, List<String>> attributes = rep.getAttributes();
        if (attributes == null || !attributes.containsKey(READ_ONLY_ROLE_ATTRIBUTE)) return Boolean.FALSE;

        List<String> readOnlyRoleAttribute = attributes.get(READ_ONLY_ROLE_ATTRIBUTE);
        if (readOnlyRoleAttribute != null && readOnlyRoleAttribute.size() > 0) {
            return Boolean.parseBoolean(readOnlyRoleAttribute.get(0));
        }
        return Boolean.FALSE;
    }

    private String[] getReadOnlyRoleRealms(RoleRepresentation rep) {
        Map<String, List<String>> attributes = rep.getAttributes();
        if (attributes == null || !attributes.containsKey(READ_ONLY_ROLE_REALMS_ATTRIBUTE)) return ArrayUtils.EMPTY_STRING_ARRAY;

        List<String> readOnlyRoleRealms = attributes.get(READ_ONLY_ROLE_REALMS_ATTRIBUTE);
        if (readOnlyRoleRealms != null && readOnlyRoleRealms.size() > 0) {
            return readOnlyRoleRealms.stream().toArray(String[]::new);
        }
        return ArrayUtils.EMPTY_STRING_ARRAY;
    }

    /**
     * Get a role by name
     *
     * @param roleName role's name (not id!)
     * @return
     */
    @Path("{role-name}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public RoleRepresentation getRole(final @PathParam("role-name") String roleName) {
        auth.roles().requireView(roleContainer);

        RoleModel roleModel = roleContainer.getRole(roleName);
        if (roleModel == null) {
            throw new NotFoundException("Could not find role");
        }

        return getRole(roleModel);
    }

    /**
     * Delete a role by name
     *
     * @param roleName role's name (not id!)
     */
    @Path("{role-name}")
    @DELETE
    @NoCache
    public void deleteRole(final @PathParam("role-name") String roleName) {
        auth.roles().requireManage(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        deleteRole(role);

        if (role.isClientRole()) {
            adminEvent.resource(ResourceType.CLIENT_ROLE);
        } else {
            adminEvent.resource(ResourceType.REALM_ROLE);
        }

        adminEvent.operation(OperationType.DELETE).resourcePath(uriInfo).success();

    }

    /**
     * Update a role by name
     *
     * @param roleName role's name (not id!)
     * @param rep
     * @return
     */
    @Path("{role-name}")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateRole(final @PathParam("role-name") String roleName, final RoleRepresentation rep) {
        auth.roles().requireManage(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        try {
            updateRole(rep, role);

            if (role.isClientRole()) {
                adminEvent.resource(ResourceType.CLIENT_ROLE);
            } else {
                adminEvent.resource(ResourceType.REALM_ROLE);
            }

            adminEvent.operation(OperationType.UPDATE).resourcePath(uriInfo).representation(rep).success();

            return Response.noContent().build();
        } catch (ModelDuplicateException e) {
            return ErrorResponse.exists("Role with name " + rep.getName() + " already exists");
        }
    }

    /**
     * Add a composite to the role
     *
     * @param roleName role's name (not id!)
     * @param roles
     */
    @Path("{role-name}/composites")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void addComposites(final @PathParam("role-name") String roleName, List<RoleRepresentation> roles) {
        auth.roles().requireManage(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        addComposites(auth, adminEvent, uriInfo, roles, role);
    }

    /**
     * Get composites of the role
     *
     * @param roleName role's name (not id!)
     * @return
     */
    @Path("{role-name}/composites")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Set<RoleRepresentation> getRoleComposites(final @PathParam("role-name") String roleName) {
        auth.roles().requireView(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        return getRoleComposites(role);
    }

    /**
     * Get realm-level roles of the role's composite
     *
     * @param roleName role's name (not id!)
     * @return
     */
    @Path("{role-name}/composites/realm")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Set<RoleRepresentation> getRealmRoleComposites(final @PathParam("role-name") String roleName) {
        auth.roles().requireView(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        return getRealmRoleComposites(role);
    }

    /**
     * An app-level roles for the specified app for the role's composite
     *
     * @param roleName role's name (not id!)
     * @param client
     * @return
     */
    @Path("{role-name}/composites/clients/{client}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Set<RoleRepresentation> getClientRoleComposites(final @PathParam("role-name") String roleName,
                                                                final @PathParam("client") String client) {
        auth.roles().requireView(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        ClientModel clientModel = realm.getClientById(client);
        if (client == null) {
            throw new NotFoundException("Could not find client");

        }
        return getClientRoleComposites(clientModel, role);
    }


    /**
     * Remove roles from the role's composite
     *
     * @param roleName role's name (not id!)
     * @param roles roles to remove
     */
    @Path("{role-name}/composites")
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    public void deleteComposites(
                                   final @PathParam("role-name") String roleName,
                                   List<RoleRepresentation> roles) {

        auth.roles().requireManage(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        deleteComposites(adminEvent, uriInfo, roles, role);
    }

    /**
     * Return object stating whether role Authoirzation permissions have been initialized or not and a reference
     *
     *
     * @param roleName
     * @return
     */
    @Path("{role-name}/management/permissions")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public ManagementPermissionReference getManagementPermissions(final @PathParam("role-name") String roleName) {
        auth.roles().requireView(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }

        AdminPermissionManagement permissions = AdminPermissions.management(session, realm);
        if (!permissions.roles().isPermissionsEnabled(role)) {
            return new ManagementPermissionReference();
        }
        return RoleByIdResource.toMgmtRef(role, permissions);
    }

    /**
     * Return object stating whether role Authoirzation permissions have been initialized or not and a reference
     *
     *
     * @param roleName
     * @return initialized manage permissions reference
     */
    @Path("{role-name}/management/permissions")
    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @NoCache
    public ManagementPermissionReference setManagementPermissionsEnabled(final @PathParam("role-name") String roleName, ManagementPermissionReference ref) {
        auth.roles().requireManage(roleContainer);
        RoleModel role = roleContainer.getRole(roleName);
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }

        AdminPermissionManagement permissions = AdminPermissions.management(session, realm);
        permissions.roles().setPermissionsEnabled(role, ref.isEnabled());
        if (ref.isEnabled()) {
            return RoleByIdResource.toMgmtRef(role, permissions);
        } else {
            return new ManagementPermissionReference();
        }
    }

    /**
     * Return List of Users that have the specified role name 
     *
     *
     * @param roleName
     * @param firstResult
     * @param maxResults
     * @return initialized manage permissions reference
     */
    @Path("{role-name}/users")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public  List<UserRepresentation> getUsersInRole(final @PathParam("role-name") String roleName, 
                                                    @QueryParam("first") Integer firstResult,
                                                    @QueryParam("max") Integer maxResults) {
        
        auth.roles().requireView(roleContainer);
        firstResult = firstResult != null ? firstResult : 0;
        maxResults = maxResults != null ? maxResults : Constants.DEFAULT_MAX_RESULTS;
        
        RoleModel role = roleContainer.getRole(roleName);
        
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        
        List<UserRepresentation> results = new ArrayList<UserRepresentation>();
        List<UserModel> userModels = session.users().getRoleMembers(realm, role, firstResult, maxResults);

        for (UserModel user : userModels) {
            results.add(ModelToRepresentation.toRepresentation(session, realm, user));
        }
        return results; 
        
    }    
    
    /**
     * Return List of Groups that have the specified role name 
     *
     *
     * @param roleName
     * @param firstResult
     * @param maxResults
     * @param briefRepresentation if false, return a full representation of the GroupRepresentation objects
     * @return
     */
    @Path("{role-name}/groups")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public  List<GroupRepresentation> getGroupsInRole(final @PathParam("role-name") String roleName, 
                                                    @QueryParam("first") Integer firstResult,
                                                    @QueryParam("max") Integer maxResults,
                                                    @QueryParam("briefRepresentation") @DefaultValue("true") boolean briefRepresentation) {
        
        auth.roles().requireView(roleContainer);
        firstResult = firstResult != null ? firstResult : 0;
        maxResults = maxResults != null ? maxResults : Constants.DEFAULT_MAX_RESULTS;
        
        RoleModel role = roleContainer.getRole(roleName);
        
        if (role == null) {
            throw new NotFoundException("Could not find role");
        }
        
        List<GroupModel> groupsModel = session.realms().getGroupsByRole(realm, role, firstResult, maxResults);

        return groupsModel.stream()
        		.map(g -> ModelToRepresentation.toRepresentation(g, !briefRepresentation))
        		.collect(Collectors.toList());
    }   
}
