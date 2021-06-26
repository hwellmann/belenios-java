package org.omadac.vote.belenios.algo;

import java.math.BigInteger;

import com.fasterxml.jackson.annotation.JsonFormat;
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
}
