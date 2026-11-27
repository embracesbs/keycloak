package org.keycloak.services.managers;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ClientManagerDescriptionTest {

    @Test
    public void masterDescriptionGetsTheMarkerOnce() {
        assertEquals("App [multi-tenant]", ClientManager.masterDescription("App"));
        assertEquals("App [multi-tenant]", ClientManager.masterDescription("App [multi-tenant]"));
    }

    @Test
    public void masterDescriptionWithoutTextIsTheMarker() {
        assertEquals("[multi-tenant]", ClientManager.masterDescription(null));
        assertEquals("[multi-tenant]", ClientManager.masterDescription(""));
    }

    @Test
    public void instanceDescriptionGetsTheInstanceMarker() {
        assertEquals("App [multi-tenant instance]", ClientManager.instanceDescription("App"));
        assertEquals("App [multi-tenant instance]", ClientManager.instanceDescription("App [multi-tenant instance]"));
    }

    @Test
    public void instanceDescriptionReplacesTheMasterMarker() {
        assertEquals("App [multi-tenant instance]", ClientManager.instanceDescription("App [multi-tenant]"));
    }

    @Test
    public void instanceDescriptionWithoutTextIsTheMarker() {
        assertEquals("[multi-tenant instance]", ClientManager.instanceDescription(null));
        assertEquals("[multi-tenant instance]", ClientManager.instanceDescription(""));
    }
}
