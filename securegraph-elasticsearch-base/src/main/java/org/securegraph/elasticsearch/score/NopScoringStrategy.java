package org.securegraph.elasticsearch.score;

import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.index.query.QueryBuilder;
import org.securegraph.*;
import org.securegraph.elasticsearch.BulkRequestWithCount;
import org.securegraph.elasticsearch.ElasticSearchSearchIndexBase;
import org.securegraph.elasticsearch.IndexInfo;
import org.securegraph.search.SearchIndex;

import java.io.IOException;

public class NopScoringStrategy extends ScoringStrategy {
    public NopScoringStrategy(GraphConfiguration graphConfiguration) {
        super(graphConfiguration);
    }

    @Override
    public void addElement(SearchIndex searchIndex, Graph graph, Element element, Authorizations authorizations) {

    }

    @Override
    public boolean addFieldsToVertexDocument(SearchIndex searchIndex, XContentBuilder jsonBuilder, Vertex vertex, GetResponse existingDocument, Authorizations authorizations) throws IOException {
        return false;
    }

    @Override
    public boolean addFieldsToEdgeDocument(SearchIndex searchIndex, XContentBuilder jsonBuilder, Edge edge, GetResponse existingDocument, Authorizations authorizations) throws IOException {
        return false;
    }

    @Override
    public int addElement(ElasticSearchSearchIndexBase searchIndex, Graph graph, BulkRequestWithCount bulkRequestWithCount, IndexInfo indexInfo, Element element, Authorizations authorizations) {
        return 0;
    }

    @Override
    public void addFieldsToElementType(XContentBuilder builder) throws IOException {

    }

    @Override
    public QueryBuilder updateQuery(QueryBuilder query) {
        return query;
    }
}
