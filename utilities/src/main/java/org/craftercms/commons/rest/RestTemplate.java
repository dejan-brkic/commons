/*
 * Copyright (C) 2007-2014 Crafter Software Corporation.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.craftercms.commons.rest;

import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;

import javax.annotation.PostConstruct;
import java.util.List;

/**
 * Simple extension of {@link org.springframework.web.client.RestTemplate} that adds the following custom
 * functionality:
 *
 * <ul>
 *     <li>Forces the use of {@link org.springframework.http.client.HttpComponentsClientHttpRequestFactory},
 *     to avoid issues with 40x responses.</li>
 *     <li>{@link org.craftercms.commons.rest.HttpMessageConvertingResponseErrorHandler} is used by default.</li>
 * </ul>
 *
 * @author avasquez
 */
public class RestTemplate extends org.springframework.web.client.RestTemplate {

    protected Class<?> errorResponseType;

    public void setErrorResponseType(Class<?> errorResponseType) {
        this.errorResponseType = errorResponseType;
    }

    public RestTemplate() {
        super(new HttpComponentsClientHttpRequestFactory());

        setErrorHandler(new HttpMessageConvertingResponseErrorHandler());
    }

    public RestTemplate(List<HttpMessageConverter<?>> messageConverters) {
        super(new HttpComponentsClientHttpRequestFactory());

        setMessageConverters(messageConverters);
        setErrorHandler(new HttpMessageConvertingResponseErrorHandler());
    }

    @PostConstruct
    public void init() {
        if (getErrorHandler() instanceof HttpMessageConvertingResponseErrorHandler) {
            HttpMessageConvertingResponseErrorHandler errorHandler =
                    (HttpMessageConvertingResponseErrorHandler) getErrorHandler();

            if (errorHandler.getMessageConverters() == null) {
                errorHandler.setMessageConverters(getMessageConverters());
            }
            if (errorHandler.getResponseType() == null && errorResponseType != null) {
                errorHandler.setResponseType(errorResponseType);
            }
        }
    }

}