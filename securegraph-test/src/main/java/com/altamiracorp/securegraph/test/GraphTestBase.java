package com.altamiracorp.securegraph.test;

import com.altamiracorp.securegraph.*;
import com.altamiracorp.securegraph.property.PropertyValue;
import com.altamiracorp.securegraph.property.StreamingPropertyValue;
import com.altamiracorp.securegraph.query.Compare;
import com.altamiracorp.securegraph.test.util.LargeStringInputStream;
import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;

import static com.altamiracorp.securegraph.test.util.IterableUtils.assertContains;
import static com.altamiracorp.securegraph.test.util.IterableUtils.count;
import static org.junit.Assert.*;

@RunWith(JUnit4.class)
public abstract class GraphTestBase {
    public static final Visibility VISIBILITY_A = new Visibility("a");
    public static final Visibility VISIBILITY_B = new Visibility("b");
    public static final Authorizations AUTHORIZATIONS_A = new Authorizations("a");
    public static final Authorizations AUTHORIZATIONS_B = new Authorizations("b");
    public static final Authorizations AUTHORIZATIONS_C = new Authorizations("c");
    public static final Authorizations AUTHORIZATIONS_A_AND_B = new Authorizations("a", "b");
    public static final int LARGE_PROPERTY_VALUE_SIZE = 1024 + 1;

    protected Graph graph;

    protected abstract Graph createGraph() throws Exception;

    public Graph getGraph() {
        return graph;
    }

    @Before
    public void before() throws Exception {
        graph = createGraph();
    }

    @After
    public void after() throws Exception {
        graph = null;
    }

    @Test
    public void testAddVertexWithId() {
        Vertex v = graph.addVertex("v1", VISIBILITY_A);
        assertNotNull(v);
        assertEquals("v1", v.getId());

        v = graph.getVertex("v1", AUTHORIZATIONS_A);
        assertNotNull(v);
        assertEquals("v1", v.getId());
        assertEquals(VISIBILITY_A, v.getVisibility());
    }

    @Test
    public void testAddVertexWithoutId() {
        Vertex v = graph.addVertex(VISIBILITY_A);
        assertNotNull(v);
        Object vertexId = v.getId();
        assertNotNull(vertexId);

        v = graph.getVertex(vertexId, AUTHORIZATIONS_A);
        assertNotNull(v);
        assertNotNull(vertexId);
    }

    @Test
    public void testAddStreamingPropertyValue() throws IOException, InterruptedException {
        String expectedLargeValue = IOUtils.toString(new LargeStringInputStream(LARGE_PROPERTY_VALUE_SIZE));
        PropertyValue propSmall = new StreamingPropertyValue(new ByteArrayInputStream("value1".getBytes()), String.class);
        PropertyValue propLarge = new StreamingPropertyValue(new ByteArrayInputStream(expectedLargeValue.getBytes()), String.class);
        Vertex v1 = graph.prepareVertex("v1", VISIBILITY_A)
                .setProperty("propSmall", propSmall, VISIBILITY_A)
                .setProperty("propLarge", propLarge, VISIBILITY_A)
                .save();

        Iterable<Object> propSmallValues = v1.getPropertyValues("propSmall");
        assertEquals(1, count(propSmallValues));
        Object propSmallValue = propSmallValues.iterator().next();
        assertTrue("propSmallValue was " + propSmallValue.getClass().getName(), propSmallValue instanceof StreamingPropertyValue);
        StreamingPropertyValue value = (StreamingPropertyValue) propSmallValue;
        assertEquals(String.class, value.getValueType());
        assertEquals("value1", IOUtils.toString(value.getInputStream(AUTHORIZATIONS_A)));
        assertEquals("value1", IOUtils.toString(value.getInputStream(AUTHORIZATIONS_A)));

        Iterable<Object> propLargeValues = v1.getPropertyValues("propLarge");
        assertEquals(1, count(propLargeValues));
        Object propLargeValue = propLargeValues.iterator().next();
        assertTrue("propLargeValue was " + propLargeValue.getClass().getName(), propLargeValue instanceof StreamingPropertyValue);
        value = (StreamingPropertyValue) propLargeValue;
        assertEquals(String.class, value.getValueType());
        assertEquals(expectedLargeValue, IOUtils.toString(value.getInputStream(AUTHORIZATIONS_A)));
        assertEquals(expectedLargeValue, IOUtils.toString(value.getInputStream(AUTHORIZATIONS_A)));

        v1 = graph.getVertex("v1", AUTHORIZATIONS_A);
        propSmallValues = v1.getPropertyValues("propSmall");
        assertEquals(1, count(propSmallValues));
        propSmallValue = propSmallValues.iterator().next();
        assertTrue("propSmallValue was " + propSmallValue.getClass().getName(), propSmallValue instanceof StreamingPropertyValue);
        value = (StreamingPropertyValue) propSmallValue;
        assertEquals(String.class, value.getValueType());
        assertEquals("value1", IOUtils.toString(value.getInputStream(AUTHORIZATIONS_A)));
        assertEquals("value1", IOUtils.toString(value.getInputStream(AUTHORIZATIONS_A)));

        propLargeValues = v1.getPropertyValues("propLarge");
        assertEquals(1, count(propLargeValues));
        propLargeValue = propLargeValues.iterator().next();
        assertTrue("propLargeValue was " + propLargeValue.getClass().getName(), propLargeValue instanceof StreamingPropertyValue);
        value = (StreamingPropertyValue) propLargeValue;
        assertEquals(String.class, value.getValueType());
        assertEquals(expectedLargeValue, IOUtils.toString(value.getInputStream(AUTHORIZATIONS_A)));
        assertEquals(expectedLargeValue, IOUtils.toString(value.getInputStream(AUTHORIZATIONS_A)));
    }

    @Test
    public void testAddVertexPropertyWithMetadata() {
        Map<String, Object> prop1Metadata = new HashMap<String, Object>();
        prop1Metadata.put("metadata1", "metadata1Value");

        graph.prepareVertex("v1", VISIBILITY_A)
                .setProperty("prop1", "value1", prop1Metadata, VISIBILITY_A)
                .save();

        Vertex v = graph.getVertex("v1", AUTHORIZATIONS_A);
        assertEquals(1, count(v.getProperties("prop1")));
        Property prop1 = v.getProperties("prop1").iterator().next();
        prop1Metadata = prop1.getMetadata();
        assertNotNull(prop1Metadata);
        assertEquals(1, prop1Metadata.keySet().size());
        assertEquals("metadata1Value", prop1Metadata.get("metadata1"));

        prop1Metadata.put("metadata2", "metadata2Value");
        v.prepareMutation()
                .setProperty("prop1", "value1", prop1Metadata, VISIBILITY_A)
                .save();

        v = graph.getVertex("v1", AUTHORIZATIONS_A);
        assertEquals(1, count(v.getProperties("prop1")));
        prop1 = v.getProperties("prop1").iterator().next();
        prop1Metadata = prop1.getMetadata();
        assertEquals(2, prop1Metadata.keySet().size());
        assertEquals("metadata1Value", prop1Metadata.get("metadata1"));
        assertEquals("metadata2Value", prop1Metadata.get("metadata2"));
    }

    @Test
    public void testAddVertexWithProperties() {
        Vertex v = graph.prepareVertex("v1", VISIBILITY_A)
                .setProperty("prop1", "value1", VISIBILITY_A)
                .setProperty("prop2", "value2", VISIBILITY_B)
                .save();
        assertEquals(1, count(v.getProperties("prop1")));
        assertEquals("value1", v.getPropertyValues("prop1").iterator().next());
        assertEquals(1, count(v.getProperties("prop2")));
        assertEquals("value2", v.getPropertyValues("prop2").iterator().next());

        v = graph.getVertex("v1", AUTHORIZATIONS_A_AND_B);
        assertEquals(1, count(v.getProperties("prop1")));
        assertEquals("value1", v.getPropertyValues("prop1").iterator().next());
        assertEquals(1, count(v.getProperties("prop2")));
        assertEquals("value2", v.getPropertyValues("prop2").iterator().next());
    }

    @Test
    public void testMultivaluedProperties() {
        Vertex v = graph.addVertex("v1", VISIBILITY_A);

        v.prepareMutation()
                .addPropertyValue("propid1a", "prop1", "value1a", VISIBILITY_A)
                .addPropertyValue("propid2a", "prop2", "value2a", VISIBILITY_A)
                .addPropertyValue("propid3a", "prop3", "value3a", VISIBILITY_A)
                .save();
        v = graph.getVertex("v1", AUTHORIZATIONS_A);
        assertEquals("value1a", v.getPropertyValues("prop1").iterator().next());
        assertEquals("value2a", v.getPropertyValues("prop2").iterator().next());
        assertEquals("value3a", v.getPropertyValues("prop3").iterator().next());
        assertEquals(3, count(v.getProperties()));

        v.prepareMutation()
                .addPropertyValue("propid1a", "prop1", "value1b", VISIBILITY_A)
                .addPropertyValue("propid2a", "prop2", "value2b", VISIBILITY_A)
                .save();
        v = graph.getVertex("v1", AUTHORIZATIONS_A);
        assertEquals(1, count(v.getPropertyValues("prop1")));
        assertEquals("value1b", v.getPropertyValues("prop1").iterator().next());
        assertEquals(1, count(v.getPropertyValues("prop2")));
        assertEquals("value2b", v.getPropertyValues("prop2").iterator().next());
        assertEquals(1, count(v.getPropertyValues("prop3")));
        assertEquals("value3a", v.getPropertyValues("prop3").iterator().next());
        assertEquals(3, count(v.getProperties()));

        v.addPropertyValue("propid1b", "prop1", "value1a-new", VISIBILITY_A);
        v = graph.getVertex("v1", AUTHORIZATIONS_A);
        assertContains("value1b", v.getPropertyValues("prop1"));
        assertContains("value1a-new", v.getPropertyValues("prop1"));
        assertEquals(4, count(v.getProperties()));
    }

    @Test
    public void testRemoveProperty() {
        Vertex v = graph.addVertex("v1", VISIBILITY_A);

        v.prepareMutation()
                .addPropertyValue("propid1a", "prop1", "value1a", VISIBILITY_A)
                .addPropertyValue("propid1b", "prop1", "value1b", VISIBILITY_A)
                .addPropertyValue("propid2a", "prop2", "value2a", VISIBILITY_A)
                .save();

        v = graph.getVertex("v1", AUTHORIZATIONS_A);
        v.removeProperty("prop1");
        assertEquals(1, count(v.getProperties()));
        v = graph.getVertex("v1", AUTHORIZATIONS_A);
        assertEquals(1, count(v.getProperties()));

        v.removeProperty("propid2a", "prop2");
        assertEquals(0, count(v.getProperties()));
        v = graph.getVertex("v1", AUTHORIZATIONS_A);
        assertEquals(0, count(v.getProperties()));
    }

    @Test
    public void testAddVertexWithVisibility() {
        graph.addVertex("v1", VISIBILITY_A);
        graph.addVertex("v2", VISIBILITY_B);

        Iterable<Vertex> cVertices = graph.getVertices(AUTHORIZATIONS_C);
        assertEquals(0, count(cVertices));

        Iterable<Vertex> aVertices = graph.getVertices(AUTHORIZATIONS_A);
        assertEquals(1, count(aVertices));
        assertEquals("v1", aVertices.iterator().next().getId());

        Iterable<Vertex> bVertices = graph.getVertices(AUTHORIZATIONS_B);
        assertEquals(1, count(bVertices));
        assertEquals("v2", bVertices.iterator().next().getId());

        Iterable<Vertex> allVertices = graph.getVertices(AUTHORIZATIONS_A_AND_B);
        assertEquals(2, count(allVertices));
    }

    @Test
    public void testRemoveVertex() {
        graph.addVertex("v1", VISIBILITY_A);

        assertEquals(1, count(graph.getVertices(AUTHORIZATIONS_A)));

        try {
            graph.removeVertex("v1", AUTHORIZATIONS_B);
        } catch (IllegalArgumentException e) {
            // expected
        }
        assertEquals(1, count(graph.getVertices(AUTHORIZATIONS_A)));

        graph.removeVertex("v1", AUTHORIZATIONS_A);
        assertEquals(0, count(graph.getVertices(AUTHORIZATIONS_A)));
    }

    @Test
    public void testRemoveVertexWithProperties() {
        graph.prepareVertex("v1", VISIBILITY_A)
                .setProperty("prop1", "value1", VISIBILITY_B)
                .save();

        assertEquals(1, count(graph.getVertices(AUTHORIZATIONS_A)));

        try {
            graph.removeVertex("v1", AUTHORIZATIONS_B);
        } catch (IllegalArgumentException e) {
            // expected
        }
        assertEquals(1, count(graph.getVertices(AUTHORIZATIONS_A)));

        graph.removeVertex("v1", AUTHORIZATIONS_A);
        assertEquals(0, count(graph.getVertices(AUTHORIZATIONS_A_AND_B)));
    }

    @Test
    public void testAddEdge() {
        Vertex v1 = graph.addVertex("v1", VISIBILITY_A);
        Vertex v2 = graph.addVertex("v2", VISIBILITY_A);
        Edge e = graph.addEdge("e1", v1, v2, "label1", VISIBILITY_A);
        assertNotNull(e);
        assertEquals("e1", e.getId());
        assertEquals("label1", e.getLabel());
        assertEquals("v1", e.getVertexId(Direction.OUT));
        assertEquals(v1, e.getVertex(Direction.OUT, AUTHORIZATIONS_A));
        assertEquals("v2", e.getVertexId(Direction.IN));
        assertEquals(v2, e.getVertex(Direction.IN, AUTHORIZATIONS_A));
        assertEquals(VISIBILITY_A, e.getVisibility());

        e = graph.getEdge("e1", AUTHORIZATIONS_B);
        assertNull(e);

        e = graph.getEdge("e1", AUTHORIZATIONS_A);
        assertNotNull(e);
        assertEquals("e1", e.getId());
        assertEquals("label1", e.getLabel());
        assertEquals("v1", e.getVertexId(Direction.OUT));
        assertEquals(v1, e.getVertex(Direction.OUT, AUTHORIZATIONS_A));
        assertEquals("v2", e.getVertexId(Direction.IN));
        assertEquals(v2, e.getVertex(Direction.IN, AUTHORIZATIONS_A));
        assertEquals(VISIBILITY_A, e.getVisibility());
    }

    @Test
    public void testGetEdge() {
        Vertex v1 = graph.addVertex("v1", VISIBILITY_A);
        Vertex v2 = graph.addVertex("v2", VISIBILITY_A);
        graph.addEdge("e1to2label1", v1, v2, "label1", VISIBILITY_A);
        graph.addEdge("e1to2label2", v1, v2, "label2", VISIBILITY_A);
        graph.addEdge("e2to1", v2, v1, "label1", VISIBILITY_A);

        v1 = graph.getVertex("v1", AUTHORIZATIONS_A);

        assertEquals(3, count(v1.getEdges(Direction.BOTH, AUTHORIZATIONS_A)));
        assertEquals(2, count(v1.getEdges(Direction.OUT, AUTHORIZATIONS_A)));
        assertEquals(1, count(v1.getEdges(Direction.IN, AUTHORIZATIONS_A)));
        assertEquals(3, count(v1.getEdges(v2, Direction.BOTH, AUTHORIZATIONS_A)));
        assertEquals(2, count(v1.getEdges(v2, Direction.OUT, AUTHORIZATIONS_A)));
        assertEquals(1, count(v1.getEdges(v2, Direction.IN, AUTHORIZATIONS_A)));
        assertEquals(2, count(v1.getEdges(v2, Direction.BOTH, "label1", AUTHORIZATIONS_A)));
        assertEquals(1, count(v1.getEdges(v2, Direction.OUT, "label1", AUTHORIZATIONS_A)));
        assertEquals(1, count(v1.getEdges(v2, Direction.IN, "label1", AUTHORIZATIONS_A)));
        assertEquals(3, count(v1.getEdges(v2, Direction.BOTH, new String[]{"label1", "label2"}, AUTHORIZATIONS_A)));
        assertEquals(2, count(v1.getEdges(v2, Direction.OUT, new String[]{"label1", "label2"}, AUTHORIZATIONS_A)));
        assertEquals(1, count(v1.getEdges(v2, Direction.IN, new String[]{"label1", "label2"}, AUTHORIZATIONS_A)));
    }

    @Test
    public void testAddEdgeWithProperties() {
        Vertex v1 = graph.addVertex("v1", VISIBILITY_A);
        Vertex v2 = graph.addVertex("v2", VISIBILITY_A);
        graph.prepareEdge("e1", v1, v2, "label1", VISIBILITY_A)
                .setProperty("propA", "valueA", VISIBILITY_A)
                .setProperty("propB", "valueB", VISIBILITY_B)
                .save();

        Edge e = graph.getEdge("e1", AUTHORIZATIONS_A);
        assertEquals(1, count(e.getProperties()));
        assertEquals("valueA", e.getPropertyValues("propA").iterator().next());
        assertEquals(0, count(e.getPropertyValues("propB")));

        e = graph.getEdge("e1", AUTHORIZATIONS_A_AND_B);
        assertEquals(2, count(e.getProperties()));
        assertEquals("valueA", e.getPropertyValues("propA").iterator().next());
        assertEquals("valueB", e.getPropertyValues("propB").iterator().next());
    }

    @Test
    public void testRemoveEdge() {
        Vertex v1 = graph.addVertex("v1", VISIBILITY_A);
        Vertex v2 = graph.addVertex("v2", VISIBILITY_A);
        graph.addEdge("e1", v1, v2, "label1", VISIBILITY_A);

        assertEquals(1, count(graph.getEdges(AUTHORIZATIONS_A)));

        try {
            graph.removeEdge("e1", AUTHORIZATIONS_B);
        } catch (IllegalArgumentException e) {
            // expected
        }
        assertEquals(1, count(graph.getEdges(AUTHORIZATIONS_A)));

        graph.removeEdge("e1", AUTHORIZATIONS_A);
        assertEquals(0, count(graph.getEdges(AUTHORIZATIONS_A)));

        v1 = graph.getVertex("v1", AUTHORIZATIONS_A);
        assertEquals(0, count(v1.getVertices(Direction.BOTH, AUTHORIZATIONS_A)));
        v2 = graph.getVertex("v2", AUTHORIZATIONS_A);
        assertEquals(0, count(v2.getVertices(Direction.BOTH, AUTHORIZATIONS_A)));
    }

    @Test
    public void testAddEdgeWithVisibility() {
        Vertex v1 = graph.addVertex("v1", VISIBILITY_A);
        Vertex v2 = graph.addVertex("v2", VISIBILITY_A);
        graph.addEdge("e1", v1, v2, "edgeA", VISIBILITY_A);
        graph.addEdge("e2", v1, v2, "edgeB", VISIBILITY_B);

        Iterable<Edge> aEdges = graph.getVertex("v1", AUTHORIZATIONS_A_AND_B).getEdges(Direction.BOTH, AUTHORIZATIONS_A);
        assertEquals(1, count(aEdges));
        Edge e1 = aEdges.iterator().next();
        assertNotNull(e1);
        assertEquals("edgeA", e1.getLabel());

        Iterable<Edge> bEdges = graph.getVertex("v1", AUTHORIZATIONS_A_AND_B).getEdges(Direction.BOTH, AUTHORIZATIONS_B);
        assertEquals(1, count(bEdges));
        Edge e2 = bEdges.iterator().next();
        assertNotNull(e2);
        assertEquals("edgeB", e2.getLabel());

        Iterable<Edge> allEdges = graph.getVertex("v1", AUTHORIZATIONS_A_AND_B).getEdges(Direction.BOTH, AUTHORIZATIONS_A_AND_B);
        assertEquals(2, count(allEdges));
    }

    @Test
    public void testGraphQuery() {
        Vertex v1 = graph.addVertex("v1", VISIBILITY_A);
        Vertex v2 = graph.addVertex("v2", VISIBILITY_A);
        graph.addEdge("e1", v1, v2, "edgeA", VISIBILITY_A);

        Iterable<Vertex> vertices = graph.query(AUTHORIZATIONS_A).vertices();
        assertEquals(2, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A).skip(1).vertices();
        assertEquals(1, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A).limit(1).vertices();
        assertEquals(1, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A).skip(1).limit(1).vertices();
        assertEquals(1, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A).skip(2).vertices();
        assertEquals(0, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A).skip(1).limit(2).vertices();
        assertEquals(1, count(vertices));

        Iterable<Edge> edges = graph.query(AUTHORIZATIONS_A).edges();
        assertEquals(1, count(edges));
    }

    @Test
    public void testGraphQueryWithQueryString() {
        Vertex v1 = graph.addVertex("v1", VISIBILITY_A);
        v1.setProperty("description", "This is vertex 1 - dog.", VISIBILITY_A);
        Vertex v2 = graph.addVertex("v2", VISIBILITY_A);
        v2.setProperty("description", "This is vertex 2 - cat.", VISIBILITY_A);

        Iterable<Vertex> vertices = graph.query("vertex", AUTHORIZATIONS_A).vertices();
        assertEquals(2, count(vertices));

        vertices = graph.query("dog", AUTHORIZATIONS_A).vertices();
        assertEquals(1, count(vertices));

        // TODO elastic search can't filter based on authorizations
//        vertices = graph.query("dog", AUTHORIZATIONS_B).vertices();
//        assertEquals(0, count(vertices));
    }

    @Test
    public void testGraphQueryHas() {
        graph.prepareVertex("v1", VISIBILITY_A)
                .setProperty("age", 25, VISIBILITY_A)
                .setProperty("birthDate", createDate(1989, 1, 5), VISIBILITY_A)
                .save();
        graph.prepareVertex("v2", VISIBILITY_A)
                .setProperty("age", 30, VISIBILITY_A)
                .setProperty("birthDate", createDate(1984, 1, 5), VISIBILITY_A)
                .save();

        Iterable<Vertex> vertices = graph.query(AUTHORIZATIONS_A)
                .has("age", Compare.EQUAL, 25)
                .vertices();
        assertEquals(1, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A)
                .has("birthDate", Compare.EQUAL, createDate(1989, 1, 5))
                .vertices();
        assertEquals(1, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A)
                .has("age", 25)
                .vertices();
        assertEquals(1, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A)
                .has("age", Compare.GREATER_THAN_EQUAL, 25)
                .vertices();
        assertEquals(2, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A)
                .has("age", Compare.GREATER_THAN, 25)
                .vertices();
        assertEquals(1, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A)
                .has("age", Compare.LESS_THAN, 26)
                .vertices();
        assertEquals(1, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A)
                .has("age", Compare.LESS_THAN_EQUAL, 25)
                .vertices();
        assertEquals(1, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A)
                .has("age", Compare.NOT_EQUAL, 25)
                .vertices();
        assertEquals(1, count(vertices));
    }

    private Date createDate(int year, int month, int day) {
        return new GregorianCalendar(year, month, day).getTime();
    }

    @Test
    public void testGraphQueryRange() {
        graph.prepareVertex("v1", VISIBILITY_A)
                .setProperty("age", 25, VISIBILITY_A)
                .save();
        graph.prepareVertex("v2", VISIBILITY_A)
                .setProperty("age", 30, VISIBILITY_A)
                .save();

        Iterable<Vertex> vertices = graph.query(AUTHORIZATIONS_A)
                .range("age", 25, 25)
                .vertices();
        assertEquals(1, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A)
                .range("age", 20, 29)
                .vertices();
        assertEquals(1, count(vertices));

        vertices = graph.query(AUTHORIZATIONS_A)
                .range("age", 25, 30)
                .vertices();
        assertEquals(2, count(vertices));
    }

    @Test
    public void testVertexQuery() {
        Vertex v1 = graph.addVertex("v1", VISIBILITY_A);
        Vertex v2 = graph.addVertex("v2", VISIBILITY_A);
        graph.addEdge("e1", v1, v2, "edgeA", VISIBILITY_A);

        v1 = graph.getVertex("v1", AUTHORIZATIONS_A);
        Iterable<Vertex> vertices = v1.query(AUTHORIZATIONS_A).vertices();
        assertEquals(1, count(vertices));
        assertEquals("v2", vertices.iterator().next().getId());

        Iterable<Edge> edges = v1.query(AUTHORIZATIONS_A).edges();
        assertEquals(1, count(edges));

        edges = v1.query(AUTHORIZATIONS_A).edges(Direction.OUT);
        assertEquals(1, count(edges));
    }

    @Test
    public void testFindPaths() {
        Vertex v1 = graph.addVertex("v1", VISIBILITY_A);
        Vertex v2 = graph.addVertex("v2", VISIBILITY_A);
        Vertex v3 = graph.addVertex("v3", VISIBILITY_A);
        Vertex v4 = graph.addVertex("v4", VISIBILITY_A);
        graph.addEdge(v1, v2, "knows", VISIBILITY_A);
        graph.addEdge(v2, v4, "knows", VISIBILITY_A);
        graph.addEdge(v1, v3, "knows", VISIBILITY_A);
        graph.addEdge(v3, v4, "knows", VISIBILITY_A);

        v1 = graph.getVertex("v1", AUTHORIZATIONS_A);
        v2 = graph.getVertex("v2", AUTHORIZATIONS_A);
        Iterable<List<Object>> paths = graph.findPaths(v1, v4, 2, AUTHORIZATIONS_A);
        assertEquals(2, count(paths));
        Iterator<List<Object>> it = paths.iterator();
        boolean found2 = false;
        boolean found3 = false;
        while (it.hasNext()) {
            List<Object> path = it.next();
            assertEquals(3, path.size());
            assertEquals(path.get(0), v1.getId());
            if (v2.getId().equals(path.get(1))) {
                found2 = true;
            } else if (v3.getId().equals(path.get(1))) {
                found3 = true;
            } else {
                fail("center of path is neither v2 or v3 but found " + path.get(1));
            }
            assertEquals(path.get(2), v4.getId());
        }
        assertTrue("v2 not found in path", found2);
        assertTrue("v3 not found in path", found3);
    }

    @Test
    public void testGetVerticesFromVertex() {
        Vertex v1 = graph.addVertex("v1", VISIBILITY_A);
        Vertex v2 = graph.addVertex("v2", VISIBILITY_A);
        Vertex v3 = graph.addVertex("v3", VISIBILITY_A);
        Vertex v4 = graph.addVertex("v4", VISIBILITY_A);
        graph.addEdge(v1, v2, "knows", VISIBILITY_A);
        graph.addEdge(v1, v3, "knows", VISIBILITY_A);
        graph.addEdge(v1, v4, "knows", VISIBILITY_A);
        graph.addEdge(v2, v3, "knows", VISIBILITY_A);

        v1 = graph.getVertex("v1", AUTHORIZATIONS_A);
        assertEquals(3, count(v1.getVertices(Direction.BOTH, AUTHORIZATIONS_A)));
        assertEquals(3, count(v1.getVertices(Direction.OUT, AUTHORIZATIONS_A)));
        assertEquals(0, count(v1.getVertices(Direction.IN, AUTHORIZATIONS_A)));

        v2 = graph.getVertex("v2", AUTHORIZATIONS_A);
        assertEquals(2, count(v2.getVertices(Direction.BOTH, AUTHORIZATIONS_A)));
        assertEquals(1, count(v2.getVertices(Direction.OUT, AUTHORIZATIONS_A)));
        assertEquals(1, count(v2.getVertices(Direction.IN, AUTHORIZATIONS_A)));

        v3 = graph.getVertex("v3", AUTHORIZATIONS_A);
        assertEquals(2, count(v3.getVertices(Direction.BOTH, AUTHORIZATIONS_A)));
        assertEquals(0, count(v3.getVertices(Direction.OUT, AUTHORIZATIONS_A)));
        assertEquals(2, count(v3.getVertices(Direction.IN, AUTHORIZATIONS_A)));

        v4 = graph.getVertex("v4", AUTHORIZATIONS_A);
        assertEquals(1, count(v4.getVertices(Direction.BOTH, AUTHORIZATIONS_A)));
        assertEquals(0, count(v4.getVertices(Direction.OUT, AUTHORIZATIONS_A)));
        assertEquals(1, count(v4.getVertices(Direction.IN, AUTHORIZATIONS_A)));
    }
}
