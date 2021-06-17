package org.omadac.vote.belenios.algo;

import java.math.BigInteger;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonMapper {

    public static final ObjectMapper INSTANCE;

    static {
        var mapper = new ObjectMapper();
        mapper.configOverride(BigInteger.class).setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));
        INSTANCE = mapper;
    }
}
