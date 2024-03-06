/*
 * Copyright 2012-2017 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jose4j.zip;

import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UncheckedJoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 */
public class DeflateRFC1951CompressionAlgorithm implements CompressionAlgorithm
{
    private static final Logger log = LoggerFactory.getLogger(DeflateRFC1951CompressionAlgorithm.class);
    public static final String DECOMPRESS_MAX_BYTES_PROPERTY_NAME = "org.jose4j.zip.decompress-max-bytes";

    private int maxDecompressedBytes = 204800;

    public DeflateRFC1951CompressionAlgorithm()
    {
        String property = System.getProperty(DECOMPRESS_MAX_BYTES_PROPERTY_NAME, "204800");
        try
        {
            maxDecompressedBytes = Integer.parseInt(property);
        }
        catch (NumberFormatException e)
        {
            log.debug("Using the default value of "+maxDecompressedBytes+" for the maximum allowed size of decompressed data " +
                    "because the system property " + DECOMPRESS_MAX_BYTES_PROPERTY_NAME + " contains an invalid value: " + e);
        }

        log.debug("");
    }

    public byte[] compress(byte[] data)
    {
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
             DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater))
        {
            deflaterOutputStream.write(data);
            deflaterOutputStream.finish();
            return byteArrayOutputStream.toByteArray();
        }
        catch (IOException e)
        {
            throw new UncheckedJoseException("Problem compressing data.", e);
        }
        finally
        {
            deflater.end();
        }
    }

    public byte[] decompress(byte[] compressedData) throws JoseException
    {
        Inflater inflater = new Inflater(true);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        try (InflaterInputStream iis = new InflaterInputStream(new ByteArrayInputStream(compressedData), inflater))
        {
            int bytesRead;
            byte[] buff = new byte[256];
            while ((bytesRead = iis.read(buff)) != -1)
            {
                byteArrayOutputStream.write(buff, 0, bytesRead);
                if (byteArrayOutputStream.size() > maxDecompressedBytes)
                {
                    throw new JoseException("Maximum allowed size of decompressed data exceeded (which is "
                            +maxDecompressedBytes+" bytes but configurable with the "+ DECOMPRESS_MAX_BYTES_PROPERTY_NAME +" system property)");
                }
            }

            return byteArrayOutputStream.toByteArray();
        }
        catch (IOException e)
        {
            throw new JoseException("Problem decompressing data.", e);
        }
        finally
        {
            inflater.end();
        }
    }

    @Override
    public String getJavaAlgorithm()
    {
        return null;
    }


    @Override
    public String getAlgorithmIdentifier()
    {
        return CompressionAlgorithmIdentifiers.DEFLATE;
    }

    @Override
    public KeyPersuasion getKeyPersuasion()
    {
        return KeyPersuasion.NONE;
    }

    @Override
    public String getKeyType()
    {
        return null;
    }

    @Override
    public boolean isAvailable()
    {
        return true;
    }
}
