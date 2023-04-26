package com.android.identity;

import android.content.Context;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;

public class AndroidStorageTest {

    @Test
    public void testStorageImplementation() {
        Context context = androidx.test.InstrumentationRegistry.getTargetContext();
        File storageDir = new File(context.getDataDir(), "ic-testing");
        StorageEngine impl = new AndroidStorageEngine(context, storageDir);

        impl.deleteAll();

        Assert.assertEquals(0, impl.enumerateData().size());

        Assert.assertNull(impl.loadData("foo"));
        byte[] data = new byte[] {1, 2, 3};
        impl.saveData("foo", data);
        Assert.assertArrayEquals(impl.loadData("foo"), data);

        Assert.assertEquals(1, impl.enumerateData().size());
        Assert.assertEquals("foo", impl.enumerateData().iterator().next());

        Assert.assertNull(impl.loadData("bar"));
        byte[] data2 = new byte[] {4, 5, 6};
        impl.saveData("bar", data2);
        Assert.assertArrayEquals(impl.loadData("bar"), data2);

        Assert.assertEquals(2, impl.enumerateData().size());

        impl.deleteData("foo");
        Assert.assertNull(impl.loadData("foo"));
        Assert.assertNotNull(impl.loadData("bar"));

        Assert.assertEquals(1, impl.enumerateData().size());

        impl.deleteData("bar");
        Assert.assertNull(impl.loadData("bar"));

        Assert.assertEquals(0, impl.enumerateData().size());
    }
}
