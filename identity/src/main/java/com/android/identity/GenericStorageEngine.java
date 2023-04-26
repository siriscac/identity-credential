package com.android.identity;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collectors;


public class GenericStorageEngine implements StorageEngine {

    private final File mStorageDirectory;

    private static final String PREFIX = "com.android.identity.Credential_";

    public GenericStorageEngine(@NonNull File storageDirectory) {
        mStorageDirectory = storageDirectory;
    }

    private File getTargetFile(String name) {
        try {
            String fileName = PREFIX + URLEncoder.encode(name, "UTF-8");
            return new File(mStorageDirectory, fileName);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Unexpected UnsupportedEncodingException", e);
        }
    }

    @Nullable
    @Override
    public byte[] loadData(String name) {
        File file = getTargetFile(name);
        try {
            if (!Files.exists(file.toPath())) {
                return null;
            }
            return Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected exception", e);
        }
    }

    @Override
    public void saveData(String name, @NonNull byte[] data) {
        File file = getTargetFile(name);
        try {
            // TODO: do this atomically
            Files.deleteIfExists(file.toPath());
            Files.write(file.toPath(), data, StandardOpenOption.CREATE_NEW);
        } catch (IOException e) {
            throw new IllegalStateException("Error writing data", e);
        }
    }

    @Override
    public void deleteData(String name) {
        File file = getTargetFile(name);
        try {
            Files.deleteIfExists(file.toPath());
        } catch (IOException e) {
            throw new IllegalStateException("Error deleting file", e);
        }
    }

    @Override
    public void deleteAll() {
        try {
            for (File file : Files.list(mStorageDirectory.toPath())
                    .map(Path::toFile)
                    .filter(File::isFile)
                    .collect(Collectors.toList())) {
                String name = file.getName();
                if (!name.startsWith(PREFIX)) {
                    continue;
                }
                Files.delete(file.toPath());
            }
        } catch (IOException e) {
            throw new IllegalStateException("Error deleting files", e);
        }
    }

    @NonNull
    @Override
    public Collection<String> enumerateData() {
        ArrayList<String> ret = new ArrayList<>();
        try {
            for (File file : Files.list(mStorageDirectory.toPath())
                    .map(Path::toFile)
                    .filter(File::isFile)
                    .collect(Collectors.toList())) {
                String name = file.getName();
                if (!name.startsWith(PREFIX)) {
                    continue;
                }
                try {
                    String decodedName = URLDecoder.decode(name.substring(PREFIX.length()), "UTF-8");
                    ret.add(decodedName);
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException(e);
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("Error deleting files", e);
        }
        return ret;
    }
}
