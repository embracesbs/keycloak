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

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ClientRepresentation;

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

        //multi-tenant client validation
        Map<String, String> attributes = client.getAttributes();
        if (attributes != null
                && attributes.containsKey(ClientModel.MULTI_TENANT)
                && TRUE.equals(Boolean.parseBoolean(attributes.get(ClientModel.MULTI_TENANT)))) {

            //todo: add validation : mt client = 'public=false', 'serviceAccountEnabled=true', attribute 'multi.tenant.service.account.roles' should exist
            //should NOT be public!
            if (TRUE.equals(client.isPublicClient())) {
                messages.add("multi-tenant-publicClient", "Multi-tenant client should NOT be public!", "multiTenantClientPublicError");
                isValid = false;
            }

            //should have service-account enabled!
            if (FALSE.equals(client.isServiceAccountsEnabled())) {
                messages.add("multi-tenant-service-accounts-enabled", "Multi-tenant client service account should be enabled!", "multiTenantServiceAccountEnableError");
                isValid = false;
            }

            // should exist attribute 'multi.tenant.service.account.roles'!
            if (FALSE.equals(attributes.containsKey(ClientModel.MULTI_TENANT_SERVICE_ACCOUNT_ROLES))
                    || attributes.get(ClientModel.MULTI_TENANT_SERVICE_ACCOUNT_ROLES) == null
                    || attributes.get(ClientModel.MULTI_TENANT_SERVICE_ACCOUNT_ROLES).isEmpty()) {
                messages.add("multi-tenant-service-account-roles-attribute", "Multi-tenant client attribute 'multi.tenant.service.account.roles' should be set!", "multiTenantServiceAccountRolesAttributeEnableError");
                isValid = false;
            }

        }

        return isValid;
    }
}
