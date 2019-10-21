/*
 * Copyright 2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.common.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.util.Collections;
import java.util.List;

import org.springframework.util.ClassUtils;

/**
 * This is a {@link SerializationStrategy} which uses a whitelist of allowed classes for deserialization.
 *
 * @author Artem Smotrakov
 * @since 2.4
 */
public class WhitelistedSerializationStrategy implements SerializationStrategy {

    /**
     * A list of classes which allowed to deserialize.
     */
    private final List<String> allowedClasses;

    /**
     * Initializes {@link WhitelistedSerializationStrategy} with specified allowed classes.
     *
     * @param allowedClasses The allowed classes for deserialization.
     */
    public WhitelistedSerializationStrategy(List<String> allowedClasses) {
        this.allowedClasses = Collections.unmodifiableList(allowedClasses);
    }

    public byte[] serialize(Object state) {
        ObjectOutputStream oos = null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(512);
            oos = new ObjectOutputStream(bos);
            oos.writeObject(state);
            oos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        } finally {
            if (oos != null) {
                try {
                    oos.close();
                } catch (IOException e) {
                    // eat it
                }
            }
        }
    }

    public <T> T deserialize(byte[] byteArray) {
        ObjectInputStream oip = null;
        try {
            oip = new WhitelistedObjectInputStream(new ByteArrayInputStream(byteArray),
                    Thread.currentThread().getContextClassLoader(), allowedClasses);
            @SuppressWarnings("unchecked")
            T result = (T) oip.readObject();
            return result;
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException(e);
        } finally {
            if (oip != null) {
                try {
                    oip.close();
                } catch (IOException e) {
                    // eat it
                }
            }
        }
    }

    /**
     * Special ObjectInputStream subclass that checks if classes are allowed to deserialize. The class
     * should be configured with a whitelist of only allowed (safe) classes to deserialize.
     */
    private static class WhitelistedObjectInputStream extends ObjectInputStream {

        /**
         * The list of classes which are allowed for deserialization.
         */
        private final List<String> allowedClasses;

        /**
         * The class loader to use for loading local classes.
         */
        private final ClassLoader classLoader;

        /**
         * Create a new WhitelistedObjectInputStream for the given InputStream, class loader and
         * allowed class names.
         *
         * @param in             The InputStream to read from.
         * @param classLoader    The ClassLoader to use for loading local classes.
         * @param allowedClasses The list of allowed classes for deserialization.
         * @throws IOException If something went wrong.
         */
        private WhitelistedObjectInputStream(InputStream in, ClassLoader classLoader, List<String> allowedClasses)
                throws IOException {
            super(in);
            this.classLoader = classLoader;
            this.allowedClasses = Collections.unmodifiableList(allowedClasses);
        }

        /**
         * Resolve the class only if it's allowed to deserialize.
         *
         * @see ObjectInputStream#resolveClass(ObjectStreamClass)
         */
        @Override
        protected Class<?> resolveClass(ObjectStreamClass classDesc)
                throws IOException, ClassNotFoundException {
            if (isProhibited(classDesc.getName())) {
                throw new NotSerializableException("Not allowed to deserialize " + classDesc.getName());
            }
            if (this.classLoader != null) {
                return ClassUtils.forName(classDesc.getName(), this.classLoader);
            }
            return super.resolveClass(classDesc);
        }

        /**
         * Check if the class is allowed to be deserialized.
         *
         * @param className The class to check.
         * @return True if the class is not allowed to be deserialized, false otherwise.
         */
        private boolean isProhibited(String className) {
            for (String allowedClass : this.allowedClasses) {
                if (className.startsWith(allowedClass)) {
                    return false;
                }
            }
            return true;
        }
    }
}
