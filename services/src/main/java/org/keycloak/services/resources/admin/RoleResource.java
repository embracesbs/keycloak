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

import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.UriInfo;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import org.apache.commons.lang.ArrayUtils;
import org.keycloak.Config;
import java.util.stream.Stream;
import static org.keycloak.models.RoleModel.READ_ONLY_ROLE_ATTRIBUTE;
import static org.keycloak.models.RoleModel.READ_ONLY_ROLE_REALMS_ATTRIBUTE;

/**
 * @resource Roles
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public abstract class RoleResource {
    protected RealmModel realm;

    public RoleResource(RealmModel realm) {
        this.realm = realm;
    }

    protected RoleRepresentation getRole(RoleModel roleModel) {
        return ModelToRepresentation.toRepresentation(roleModel);
    }

    protected void deleteRole(RoleModel role) {
        if (!role.getContainer().removeRole(role)) {
            throw new NotFoundException("Role not found");
        }
    }

    protected void updateRole(RoleRepresentation rep, RoleModel role) {
        role.setName(rep.getName());
        role.setDescription(rep.getDescription());

        if (rep.getAttributes() != null) {
            Set<String> attrsToRemove = new HashSet<>(role.getAttributes().keySet());
            attrsToRemove.removeAll(rep.getAttributes().keySet());

            for (Map.Entry<String, List<String>> attr : rep.getAttributes().entrySet()) {
                role.setAttribute(attr.getKey(), attr.getValue());
            }

            for (String attr : attrsToRemove) {
                role.removeAttribute(attr);
            }
        }
    }

    protected void addComposites(AdminPermissionEvaluator auth, AdminEventBuilder adminEvent, UriInfo uriInfo, List<RoleRepresentation> roles, RoleModel role) {
        for (RoleRepresentation rep : roles) {
            if (rep.getId() == null) throw new NotFoundException("Could not find composite role");
            RoleModel composite = realm.getRoleById(rep.getId());
            if (composite == null) {
                throw new NotFoundException("Could not find composite role");
            }
            auth.roles().requireMapComposite(composite);
            role.addCompositeRole(composite);
        }

        if (role.isClientRole()) {
            adminEvent.resource(ResourceType.CLIENT_ROLE);
        } else {
            adminEvent.resource(ResourceType.REALM_ROLE);
        }

        adminEvent.operation(OperationType.CREATE).resourcePath(uriInfo).representation(roles).success();
    }

    protected Stream<RoleRepresentation> getRealmRoleComposites(RoleModel role) {
        return role.getCompositesStream()
                .filter(composite -> composite.getContainer() instanceof RealmModel)
                .map(ModelToRepresentation::toBriefRepresentation);
    }

    protected Stream<RoleRepresentation> getClientRoleComposites(ClientModel app, RoleModel role) {
        return role.getCompositesStream()
                .filter(composite -> Objects.equals(composite.getContainer(), app))
                .map(ModelToRepresentation::toBriefRepresentation);
    }

    protected void deleteComposites(AdminEventBuilder adminEvent, UriInfo uriInfo, List<RoleRepresentation> roles, RoleModel role) {
        for (RoleRepresentation rep : roles) {
            RoleModel composite = realm.getRoleById(rep.getId());
            if (composite == null) {
                throw new NotFoundException("Could not find composite role");
            }
            role.removeCompositeRole(composite);
        }

        if (role.isClientRole()) {
            adminEvent.resource(ResourceType.CLIENT_ROLE);
        } else {
            adminEvent.resource(ResourceType.REALM_ROLE);
        }

        adminEvent.operation(OperationType.DELETE).resourcePath(uriInfo).representation(roles).success();
    }

    protected void setupReadonlyRoleRegistrations(KeycloakSession session, RoleModel role, RoleRepresentation rep) {
        RealmModel adminRealm = session.realms().getRealm(Config.getAdminRealm());

        List<RealmModel> allRealms = session.realms().getRealms();

        String[] viewRoles = Arrays.stream(AdminRoles.ALL_REALM_ROLES)
                .filter(r -> r.startsWith("view-"))
                .toArray(String[]::new);

        String[] readOnlyRoles = Stream.of(viewRoles, AdminRoles.ALL_QUERY_ROLES)
                .flatMap(Stream::of)
                .toArray(String[]::new);

        String[] explicitRealmsFilter = getReadOnlyRoleRealmsFilter(rep);
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
                    //logger.errorf("read-only role registration -> master app role with name '%s' not found in app '%s'!", roleName, masterAdminAppName);
                    continue;
                }

                // and composite to the readonly role
                role.addCompositeRole(foundRole);
            }
        }
    }

    protected boolean isReadOnly(RoleRepresentation rep) {
        Map<String, List<String>> attributes = rep.getAttributes();
        if (attributes == null || !attributes.containsKey(READ_ONLY_ROLE_ATTRIBUTE)) return Boolean.FALSE;

        List<String> readonlyAttr = attributes.get(READ_ONLY_ROLE_ATTRIBUTE);
        if (readonlyAttr == null) return Boolean.FALSE;

        String[] readOnlyRoleAttribute = readonlyAttr.toArray(new String[0]);
        if (ArrayUtils.isNotEmpty(readOnlyRoleAttribute)) {
            return Boolean.parseBoolean(readOnlyRoleAttribute[0]);
        }
        return Boolean.FALSE;
    }

    protected String[] getReadOnlyRoleRealmsFilter(RoleRepresentation rep) {
        Map<String, List<String>> attributes = rep.getAttributes();
        if (attributes == null || !attributes.containsKey(READ_ONLY_ROLE_REALMS_ATTRIBUTE))
            return ArrayUtils.EMPTY_STRING_ARRAY;

        List<String> filterRealms = attributes.get(READ_ONLY_ROLE_REALMS_ATTRIBUTE);
        if (filterRealms == null) return ArrayUtils.EMPTY_STRING_ARRAY;

        String[] readOnlyRoleRealms = filterRealms.toArray(new String[0]);
        if (ArrayUtils.isNotEmpty(readOnlyRoleRealms)) {
            return readOnlyRoleRealms;
        }
        return ArrayUtils.EMPTY_STRING_ARRAY;
    }
}
