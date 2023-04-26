package com.android.identity;

import android.content.Context;
import android.util.AtomicFile;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;

public class AndroidStorageEngine implements StorageEngine {

    // TODO: maybe encrypt data we store on disk to support Android devices without disk encryption.

    private static final String PREFIX = "com.android.identity.Credential_";

    private final Context mContext;
    private final File mStorageDirectory;

    public AndroidStorageEngine(@NonNull Context context,
                                @NonNull File storageDirectory) {
        mContext = context;
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
        AtomicFile file = new AtomicFile(getTargetFile(name));
        try {
            return file.readFully();
        } catch(FileNotFoundException e) {
            return null;
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected exception", e);
        }
    }

    @Override
    public void saveData(String name, @NonNull byte[] data) {
        AtomicFile file = new AtomicFile(getTargetFile(name));
        FileOutputStream outputStream = null;
        try {
            outputStream = file.startWrite();
            outputStream.write(data);
            file.finishWrite(outputStream);
        } catch (IOException e) {
            if (outputStream != null) {
                file.failWrite(outputStream);
            }
            throw new IllegalStateException("Error writing data", e);
        }
    }

    @Override
    public void deleteData(String name) {
        AtomicFile file = new AtomicFile(getTargetFile(name));
        file.delete();
    }

    @Override
    public void deleteAll() {
        for (File file : mStorageDirectory.listFiles()) {
            String name = file.getName();
            if (!name.startsWith(PREFIX)) {
                continue;
            }
            file.delete();
        }
    }

    @Override
    @NonNull
    public Collection<String> enumerateData() {
        ArrayList<String> ret = new ArrayList<>();
        for (File file : mStorageDirectory.listFiles()) {
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
        return ret;
    }
}
