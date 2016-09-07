package org.securegraph.accumulo.migrations;

import com.beust.jcommander.Parameter;
import org.apache.accumulo.core.cli.MapReduceClientOnRequiredTable;
import org.apache.accumulo.core.client.AccumuloSecurityException;
import org.apache.accumulo.core.client.mapreduce.AccumuloInputFormat;
import org.apache.accumulo.core.client.mapreduce.AccumuloOutputFormat;
import org.apache.accumulo.core.data.Mutation;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;
import org.securegraph.accumulo.AccumuloGraphConfiguration;
import org.securegraph.accumulo.serializer.ValueSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public abstract class MRMigrationBase extends Configured implements Tool {
    private static final Logger LOGGER = LoggerFactory.getLogger(MRMigrationBase.class);

    protected static void run(MRMigrationBase mr, String[] args) throws Exception {
        int res = ToolRunner.run(new Configuration(), mr, args);
        System.exit(res);
    }

    public static ValueSerializer getValueSerializer(Configuration conf) {
        return getAccumuloGraphConfiguration(conf).createValueSerializer();
    }

    public static String getOutputTableName(Configuration conf) {
        return conf.get("MRMigrationBase.output.tableName");
    }

    public static AccumuloGraphConfiguration getAccumuloGraphConfiguration(Configuration conf) {
        return new AccumuloGraphConfiguration(conf, conf.get("MRMigrationBase.config.prefix"));
    }

    protected abstract static class Opts extends MapReduceClientOnRequiredTable {
        @Parameter(
                names = {"-cp", "--configprefix"},
                description = "Configuration prefix"
        )
        public String configPrefix = "graph";

        @Override
        public void setAccumuloConfigs(Job job) throws AccumuloSecurityException {
            super.setAccumuloConfigs(job);

            AccumuloInputFormat.setConnectorInfo(job, getPrincipal(), this.getToken());
            AccumuloOutputFormat.setConnectorInfo(job, getPrincipal(), this.getToken());

            AccumuloInputFormat.setInputTableName(job, getTableName());
            AccumuloInputFormat.setScanAuthorizations(job, this.auths);
            AccumuloOutputFormat.setCreateTables(job, true);
            AccumuloOutputFormat.setDefaultTableName(job, getTableName());

            job.getConfiguration().set("MRMigrationBase.config.prefix", configPrefix);
            job.getConfiguration().set("MRMigrationBase.output.tableName", getTableName());
        }

        public abstract String getTableName();
    }

    protected static class OptsWithTableName extends Opts {
        @Parameter(
                names = {"-t", "--table"},
                description = "Name of table to migrate"
        )
        public String tableName = System.getProperty("table.name");

        @Override
        public String getTableName() {
            return tableName;
        }
    }

    protected abstract static class MRMigrationMapperBase<TKey, TValue> extends Mapper<TKey, TValue, Text, Mutation> {
        private ValueSerializer valueSerializer;
        private Text outputTableNameText;

        @Override
        protected void setup(Context context) throws IOException, InterruptedException {
            super.setup(context);
            valueSerializer = MRMigrationBase.getValueSerializer(context.getConfiguration());
            outputTableNameText = new Text(MRMigrationBase.getOutputTableName(context.getConfiguration()));
        }

        @Override
        protected void map(TKey key, TValue value, Context context) throws IOException, InterruptedException {
            try {
                safeMap(key, value, context);
            } catch (Throwable ex) {
                LOGGER.error("Failed to process row: " + key, ex);
            }
        }

        protected abstract void safeMap(TKey key, TValue value, Context context) throws Exception;

        public ValueSerializer getValueSerializer() {
            return valueSerializer;
        }

        protected Text getOutputTableNameText() {
            return outputTableNameText;
        }
    }

    @Override
    public int run(String[] args) throws Exception {
        Opts opts = createOpts();
        opts.parseArgs(getClass().getName(), args);

        Job job = Job.getInstance(getConf(), getClass().getSimpleName());
        job.setJarByClass(getClass());
        opts.setAccumuloConfigs(job);

        job.setInputFormatClass(getInputFormatClass());

        job.setMapperClass(getMigrationMapperClass());
        job.setMapOutputKeyClass(Text.class);
        job.setMapOutputValueClass(Mutation.class);

        job.setNumReduceTasks(0);

        job.setOutputFormatClass(AccumuloOutputFormat.class);

        job.waitForCompletion(true);
        return job.isSuccessful() ? 0 : 1;
    }

    protected Class getInputFormatClass() {
        return AccumuloInputFormat.class;
    }

    protected Opts createOpts() {
        return new OptsWithTableName();
    }

    protected abstract Class<? extends Mapper> getMigrationMapperClass();
}
