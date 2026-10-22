package com.keyforge.cyberarkpoc.model;

import java.util.List;

/**
 * GetRole result. Fields per the official Roles API reference: {@code Uuid}, {@code Name},
 * {@code Description}, {@code RoleType}, {@code Principals}. What a {@code Principals} entry holds
 * (an id, a name) is not documented; the list is kept as given and only its size is reported.
 */
public record RoleDetails(String id, String name, String description, String roleType, List<String> principals) {
}
