package com.android.identity;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Collection;

/**
 * A simple interface to store and retrieve data, organized by file name.
 *
 * <p>Data is organized by file names. Directories are not supported.
 */
public interface StorageEngine {

    /**
     * Loads data.
     *
     * @param name the name of the file to load.
     * @return The stored data, as a binary blob or {@code null} if there is no data.
     */
    @Nullable byte[] loadData(String name);

    /**
     * Saves data.
     *
     * @param name the name of the file to load.
     * @param data the data to store.
     */
    void saveData(String name, @NonNull byte[] data);

    /**
     * Deletes data.
     *
     * <p>If there is no data for the given file name, this is a no-op.
     *
     * @param name the name of the file to delete.
     */
    void deleteData(String name);

    /**
     * Deletes all files
     */
    void deleteAll();

    /**
     * Enumerates the files currently stored.
     *
     * @return A collection of file names.
     */
    @NonNull
    Collection<String> enumerateData();
}
