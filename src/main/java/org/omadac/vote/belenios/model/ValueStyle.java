package org.omadac.vote.belenios.model;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.immutables.value.Value;
import org.immutables.value.Value.Style.ValidationMethod;

@Target({ElementType.PACKAGE, ElementType.TYPE})
@Retention(RetentionPolicy.CLASS)
@Value.Style(typeAbstract = {"*Spec"},

    defaultAsDefault = false,

    depluralize = true,

    get = "",

    typeImmutable = "*",

    validationMethod = ValidationMethod.NONE)
public @interface ValueStyle {
}
