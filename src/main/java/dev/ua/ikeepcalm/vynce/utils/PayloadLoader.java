package dev.ua.ikeepcalm.vynce.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class PayloadLoader {

    private static final Logger logger = LoggerFactory.getLogger(PayloadLoader.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    public static List<String> loadPayloads(String filename, String category) {
        List<String> payloads = new ArrayList<>();

        try (InputStream is = PayloadLoader.class.getClassLoader()
                .getResourceAsStream("payloads/" + filename)) {

            if (is == null) {
                logger.error("Payload file not found: payloads/{}", filename);
                return payloads;
            }

            JsonNode root = mapper.readTree(is);
            JsonNode categoryNode = root.get(category);

            if (categoryNode != null && categoryNode.isArray()) {
                categoryNode.forEach(node -> payloads.add(node.asText()));
            }

        } catch (Exception e) {
            logger.error("Failed to load payloads from {}: {}", filename, e.getMessage(), e);
        }

        return payloads;
    }

    public static List<String> loadAllPayloads(String filename) {
        List<String> allPayloads = new ArrayList<>();

        try (InputStream is = PayloadLoader.class.getClassLoader()
                .getResourceAsStream("payloads/" + filename)) {

            if (is == null) {
                logger.error("Payload file not found: payloads/{}", filename);
                return allPayloads;
            }

            JsonNode root = mapper.readTree(is);
            root.fields().forEachRemaining(entry -> {
                JsonNode arrayNode = entry.getValue();
                if (arrayNode.isArray()) {
                    arrayNode.forEach(node -> allPayloads.add(node.asText()));
                }
            });

        } catch (Exception e) {
            logger.error("Failed to load payloads from {}: {}", filename, e.getMessage(), e);
        }

        return allPayloads;
    }
}
