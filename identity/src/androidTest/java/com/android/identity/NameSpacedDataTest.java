package com.android.identity;

import androidx.annotation.NonNull;

import org.junit.Assert;
import org.junit.Test;

import co.nstant.in.cbor.model.DataItem;

public class NameSpacedDataTest {

    static void
    checkNameSpaced(@NonNull NameSpacedData nameSpacedData) {
        Assert.assertEquals(2, nameSpacedData.getNameSpaceNames().size());
        Assert.assertEquals("ns1", nameSpacedData.getNameSpaceNames().get(0));
        Assert.assertEquals("ns2", nameSpacedData.getNameSpaceNames().get(1));
        Assert.assertEquals(3, nameSpacedData.getDataElementNames("ns1").size());
        Assert.assertArrayEquals(Util.cborEncodeString("bar1"), nameSpacedData.getDataElementValue("ns1", "foo1"));
        Assert.assertArrayEquals(Util.cborEncodeString("bar2"), nameSpacedData.getDataElementValue("ns1", "foo2"));
        Assert.assertArrayEquals(Util.cborEncodeString("bar3"), nameSpacedData.getDataElementValue("ns1", "foo3"));
        Assert.assertEquals(2, nameSpacedData.getDataElementNames("ns2").size());
        Assert.assertArrayEquals(Util.cborEncodeString("foo1"), nameSpacedData.getDataElementValue("ns2", "bar1"));
        Assert.assertArrayEquals(Util.cborEncodeString("foo2"), nameSpacedData.getDataElementValue("ns2", "bar2"));
    }

    @Test
    public void testNameSpacedData() {
        NameSpacedData nameSpacedData = new NameSpacedData.Builder()
                .putEntryString("ns1", "foo1", "bar1")
                .putEntryString("ns1", "foo2", "bar2")
                .putEntryString("ns1", "foo3", "bar3")
                .putEntryString("ns2", "bar1", "foo1")
                .putEntryString("ns2", "bar2", "foo2")
                .build();
        DataItem asCbor = nameSpacedData.toCbor();
        Assert.assertEquals("{\n" +
                        "  \"ns1\": {\n" +
                        "    \"foo1\": h'6462617231',\n" +
                        "    \"foo2\": h'6462617232',\n" +
                        "    \"foo3\": h'6462617233'\n" +
                        "  },\n" +
                        "  \"ns2\": {\n" +
                        "    \"bar1\": h'64666f6f31',\n" +
                        "    \"bar2\": h'64666f6f32'\n" +
                        "  }\n" +
                        "}",
                CborUtil.toDiagnostics(asCbor, CborUtil.DIAGNOSTICS_FLAG_PRETTY_PRINT));

        checkNameSpaced(nameSpacedData);

        NameSpacedData decoded = NameSpacedData.fromCbor(asCbor);
        checkNameSpaced(decoded);
    }

}
