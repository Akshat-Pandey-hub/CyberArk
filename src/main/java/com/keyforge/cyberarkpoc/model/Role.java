package com.keyforge.cyberarkpoc.model;

/** A role row from the Redrock {@code Role} table. {@code description} is an ASSUMED column. */
public record Role(String id, String name, String description) {
}
