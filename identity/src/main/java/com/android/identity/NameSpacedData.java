package com.android.identity;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;

public class NameSpacedData {
    private LinkedHashMap<String, LinkedHashMap<String, byte[]>> mMap;

    public NameSpacedData() {
        mMap = new LinkedHashMap<>();
    }

    private NameSpacedData(LinkedHashMap<String, LinkedHashMap<String, byte[]>> map) {
        mMap = map;
    }

    public List<String> getNameSpaceNames() {
        List<String> ret = new ArrayList<>();
        for (String nameSpaceName : mMap.keySet()) {
            ret.add(nameSpaceName);
        }
        return ret;
    }

    public @NonNull List<String> getDataElementNames(@NonNull String nameSpaceName) {
        LinkedHashMap<String, byte[]> innerMap = mMap.get(nameSpaceName);
        if (innerMap == null) {
            throw new IllegalArgumentException("No such namespace '" + nameSpaceName + "'");
        }
        List<String> ret = new ArrayList<>();
        for (String dataElementName : innerMap.keySet()) {
            ret.add(dataElementName);
        }
        return ret;
    }

    public @NonNull byte[] getDataElementValue(@NonNull String nameSpaceName,
                                               @NonNull String dataElementName) {
        LinkedHashMap<String, byte[]> innerMap = mMap.get(nameSpaceName);
        if (innerMap == null) {
            throw new IllegalArgumentException("No such namespace '" + nameSpaceName + "'");
        }
        byte[] value = innerMap.get(dataElementName);
        if (value == null) {
            throw new IllegalArgumentException("No such data element '" + dataElementName + "'");
        }
        return value;
    }

    static NameSpacedData fromCbor(@NonNull DataItem dataItem) {
        LinkedHashMap<String, LinkedHashMap<String, byte[]>> ret = new LinkedHashMap<>();
        if (!(dataItem instanceof co.nstant.in.cbor.model.Map)) {
            throw new IllegalStateException("dataItem is not a map");
        }
        for (DataItem nameSpaceNameItem : ((co.nstant.in.cbor.model.Map) dataItem).getKeys()) {
            if (!(nameSpaceNameItem instanceof UnicodeString)) {
                throw new IllegalStateException("Expected string for namespace name");
            }
            String namespaceName = ((UnicodeString) nameSpaceNameItem).getString();
            LinkedHashMap<String, byte[]> dataElementToValueMap = new LinkedHashMap<>();
            DataItem dataElementItems = Util.cborMapExtractMap(dataItem, namespaceName);
            if (!(dataElementItems instanceof co.nstant.in.cbor.model.Map)) {
                throw new IllegalStateException("Expected map");
            }
            for (DataItem dataElementNameItem : ((co.nstant.in.cbor.model.Map) dataElementItems).getKeys()) {
                if (!(dataElementNameItem instanceof UnicodeString)) {
                    throw new IllegalStateException("Expected string for data element name");
                }
                String dataElementName = ((UnicodeString) dataElementNameItem).getString();
                DataItem valueItem = ((co.nstant.in.cbor.model.Map) dataElementItems).get(dataElementNameItem);
                if (!(valueItem instanceof ByteString)) {
                    throw new IllegalStateException("Expected bytestring for data element value");
                }
                byte[] value = ((ByteString) valueItem).getBytes();
                dataElementToValueMap.put(dataElementName, value);
            }
            ret.put(namespaceName, dataElementToValueMap);
        }
        return new NameSpacedData(ret);
    }

    DataItem toCbor() {
        CborBuilder builder = new CborBuilder();
        MapBuilder<CborBuilder> mapBuilder = builder.addMap();
        for (String namespaceName : mMap.keySet()) {
            MapBuilder<MapBuilder<CborBuilder>> innerMapBuilder = mapBuilder.putMap(namespaceName);
            LinkedHashMap<String, byte[]> namespace = mMap.get(namespaceName);
            for (String dataElementName : namespace.keySet()) {
                byte[] dataElementValue = namespace.get(dataElementName);
                innerMapBuilder.put(dataElementName, dataElementValue);
            }
        }
        return builder.build().get(0);
    }

    /**
     * A builder for {@link NameSpacedData}.
     */
    public static class Builder {
        LinkedHashMap<String, LinkedHashMap<String, byte[]>> mMap = new LinkedHashMap<>();
        public Builder() {}

        public @NonNull Builder putEntry(@NonNull String nameSpaceName,
                                         @NonNull String dataElementName,
                                         @NonNull byte[] value) {
            LinkedHashMap<String, byte[]> innerMap = mMap.get(nameSpaceName);
            if (innerMap == null) {
                innerMap = new LinkedHashMap<>();
                mMap.put(nameSpaceName, innerMap);
            }
            // TODO: validate/verify that value is proper CBOR.
            innerMap.put(dataElementName, value);
            return this;
        }

        public @NonNull Builder putEntryString(@NonNull String nameSpaceName,
                                               @NonNull String dataElementName,
                                               @NonNull String value) {
            return putEntry(nameSpaceName, dataElementName, Util.cborEncodeString(value));
        }

        public @NonNull Builder putEntryByteString(@NonNull String nameSpaceName,
                                               @NonNull String dataElementName,
                                               @NonNull byte[] value) {
            return putEntry(nameSpaceName, dataElementName, Util.cborEncodeBytestring(value));
        }

        public @NonNull Builder putEntryNumber(@NonNull String nameSpaceName,
                                               @NonNull String dataElementName,
                                               long value) {
            return putEntry(nameSpaceName, dataElementName, Util.cborEncodeNumber(value));
        }

        public @NonNull Builder putEntryBoolean(@NonNull String nameSpaceName,
                                                @NonNull String dataElementName,
                                                boolean value) {
            return putEntry(nameSpaceName, dataElementName, Util.cborEncodeBoolean(value));
        }

        public @NonNull NameSpacedData build() {
            return new NameSpacedData(mMap);
        }

    }
}
