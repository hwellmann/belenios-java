package org.omadac.vote.belenios.quarkus;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;

import org.immutables.annotate.InjectAnnotation;
import org.immutables.annotate.InjectAnnotation.Where;

import io.quarkus.runtime.annotations.RegisterForReflection;

@InjectAnnotation(type = RegisterForReflection.class, target = {Where.IMMUTABLE_TYPE, Where.BUILDER_TYPE})
@Retention(RUNTIME)
public @interface InjectReflectionSupport {

}
