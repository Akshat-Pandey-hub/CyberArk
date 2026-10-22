package com.keyforge.cyberarkpoc.config;

/** Invalid or missing CyberArk connection settings. */
public class ConfigException extends RuntimeException {
    public ConfigException(String message) {
        super(message);
    }
}
