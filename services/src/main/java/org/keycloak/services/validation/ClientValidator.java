/*
 *
 *  * Copyright 2016 Red Hat, Inc. and/or its affiliates
 *  * and other contributors as indicated by the @author tags.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.keycloak.services.validation;

import org.keycloak.models.AdminRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ClientRepresentation;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static java.lang.Boolean.TRUE;
import static java.lang.Boolean.FALSE;

/**
 * @author Vaclav Muzikar <vmuzikar@redhat.com>
 */
public class ClientValidator {
    /**
     * Checks if the Client's Redirect URIs doesn't contain any URI fragments (like http://example.org/auth#fragment)
     *
     * @see <a href="https://issues.jboss.org/browse/KEYCLOAK-3421">KEYCLOAK-3421</a>
     * @param client
     * @param messages
     * @return true if Redirect URIs doesn't contain any URI with fragments
     */
    public static boolean validate(ClientRepresentation client, ValidationMessages messages) {
        boolean isValid = true;

        if (client.getRedirectUris() != null) {
            long urisWithFragmentCount = client.getRedirectUris().stream().filter(p -> p.contains("#")).count();
            if (urisWithFragmentCount > 0) {
                messages.add("redirectUris", "Redirect URIs must not contain an URI fragment", "clientRedirectURIsFragmentError");
                isValid = false;
            }
        }

        if (client.getRootUrl() != null && client.getRootUrl().contains("#")) {
            messages.add("rootUrl", "Root URL must not contain an URL fragment", "clientRootURLFragmentError");
            isValid = false;
        }

        // multi-tenant client validation
        Map<String, String> attributes = client.getAttributes();
        if (attributes != null
                && attributes.containsKey(ClientModel.MULTI_TENANT)
                && TRUE.equals(Boolean.parseBoolean(attributes.get(ClientModel.MULTI_TENANT)))) {

            // should NOT be public!
            if (TRUE.equals(client.isPublicClient())) {
                messages.add("multi-tenant-publicClient", "Multi-tenant client validation: should NOT be public!", "multiTenantClientPublicError");
                isValid = false;
            }

            // should have service-account enabled!
            if (FALSE.equals(client.isServiceAccountsEnabled())) {
                messages.add("multi-tenant-service-accounts-enabled", "Multi-tenant client validation: service account should be enabled!", "multiTenantServiceAccountEnableError");
                isValid = false;
            }

            // should exist attribute 'multi.tenant.service.account.roles'!
            if (FALSE.equals(attributes.containsKey(ClientModel.MULTI_TENANT_SERVICE_ACCOUNT_ROLES))
                    || attributes.get(ClientModel.MULTI_TENANT_SERVICE_ACCOUNT_ROLES) == null
                    || attributes.get(ClientModel.MULTI_TENANT_SERVICE_ACCOUNT_ROLES).isEmpty()) {
                messages.add("multi-tenant-service-account-roles-attribute", "Multi-tenant client validation: attribute 'multi.tenant.service.account.roles' should be set!", "multiTenantServiceAccountRolesAttributeEnableError");
                isValid = false;
            }

            // should be valid admin role names
            String[] roleAttributes = client.getAttributes()
                    .get(ClientModel.MULTI_TENANT_SERVICE_ACCOUNT_ROLES)
                    .replaceAll("\\s+", "")
                    .split(",");

            for (String role : roleAttributes) {
                if (Arrays.stream(AdminRoles.ALL_REALM_ROLES).noneMatch(r -> r.equals(role))) {
                    messages.add("multi-tenant-service-account-roles-attribute", String.format("Multi-tenant client validation: un-existent admin role name '%s'", role), "multiTenantServiceAccountRolesAttributeNonExistentError");
                    isValid = false;
                }
            }
        }

        return isValid;
    }
}
