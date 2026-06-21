package io.poly.candor;

import io.poly.candor.model.Effector;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * `commonPrefix` + `layerOf` — the package-layer attribution that underpins the `containment` diagnostic and
 * its AS-EFF-010 ratchet. An off-by-one here silently misattributes every method's layer, corrupting the gate.
 */
class LayerOfTest {

    /** The layer is the PACKAGE segment after the common prefix — only when a `Class.method` pair (2 segments)
     *  follows it; a class in the root (no package layer left) buckets into `(root)`. */
    @Test
    void layerIsThePackageSegmentAfterThePrefix() {
        // app.web.Ctl.handle, prefix "app" (len 1): segs=[app,web,Ctl,handle], 1+2=3 < 4 → segs[1]="web"
        assertEquals("web", Query.layerOf("app.web.Ctl.handle", 1));
        assertEquals("repo", Query.layerOf("app.repo.Dao.find", 1));
        // a class directly under the prefix (no package layer left): app.Root.method, len 1 → 1+2=3 !< 3 → (root)
        assertEquals("(root)", Query.layerOf("app.Root.method", 1));
        // no prefix at all (len 0): a.B.c → 0+2=2 !< 3 → ... segs=[a,B,c], 2<3 → segs[0]="a"
        assertEquals("a", Query.layerOf("a.b.C.m", 0));
    }

    /** commonPrefix is the shared leading dotted segments across all functions. */
    @Test
    void commonPrefixIsSharedLeadingSegments() throws Exception {
        Path rep = Files.createTempFile("cp", ".json");
        Files.writeString(rep, """
            {"functions":[
              {"fn":"app.web.Ctl.handle","direct":["Db"]},
              {"fn":"app.repo.Dao.find","direct":["Db"]}
            ]}""");
        rep.toFile().deleteOnExit();
        List<Effector> fns = Query.load(rep.toString());
        assertArrayEquals(new String[] {"app"}, Query.commonPrefix(fns));
        // and the layer attribution composes: each function's layer is its package under that prefix
        int pl = Query.commonPrefix(fns).length;
        assertEquals("web", Query.layerOf("app.web.Ctl.handle", pl));
        assertEquals("repo", Query.layerOf("app.repo.Dao.find", pl));
    }
}
