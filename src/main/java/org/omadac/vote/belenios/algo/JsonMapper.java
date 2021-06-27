package org.omadac.vote.belenios.algo;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;

public class JsonMapper {

    public static final ObjectMapper INSTANCE;

    static {
        var mapper = new ObjectMapper();
        mapper.registerModule(new Jdk8Module());
        mapper.configOverride(BigInteger.class).setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));
        INSTANCE = mapper;
    }

    public static <T> T fromJson(String json, Class<T> klass) {
        try {
            return INSTANCE.readValue(json, klass);
        }
        catch (JsonProcessingException exc) {
            throw new IllegalArgumentException("Cannot parse JSON", exc);
        }
    }

    public static <T> T fromJson(File json, Class<T> klass) {
        try {
            return INSTANCE.readValue(json, klass);
        }
        catch (JsonProcessingException exc) {
            throw new IllegalArgumentException("Cannot parse JSON", exc);
        }
        catch (IOException exc) {
            throw new IllegalArgumentException("Cannot read from file " + json, exc);
        }
    }
}
