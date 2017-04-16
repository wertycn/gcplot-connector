package com.gcplot.connector;

import com.amazonaws.services.s3.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class S3ResourceManager {
    private static final Logger LOG = LoggerFactory.getLogger(S3ResourceManager.class);
    private final S3Connector connector;
    private final String basePath;
    private final String accountId;
    private final String analyzeId;

    public S3ResourceManager(S3Connector connector, String basePath, String accountId, String analyzeId) {
        this.connector = connector;
        this.basePath = basePath;
        this.accountId = accountId;
        this.analyzeId = analyzeId;
    }

    public void upload(File file, String jvmId) {
        List<PartETag> partETags = new ArrayList<>();

        String newPath = Utils.toBase64(accountId) + "/" + analyzeId + "/" + jvmId;
        newPath = (basePath.length() > 0 ? basePath : "") + newPath + "/" + file.getName();
        // Step 1: Initialize.
        ObjectMetadata om = new ObjectMetadata();
        String contentType = null;
        try {
            contentType = Files.probeContentType(file.toPath());
        } catch (IOException ignored) {
        }
        if (contentType != null) {
            om.addUserMetadata("Content-Type", contentType);
        }
        InitiateMultipartUploadRequest initRequest;
        InitiateMultipartUploadResult initResponse = null;

        try {
            LOG.debug("S3: Uploading to {}", newPath);
            initRequest = new InitiateMultipartUploadRequest(connector.getBucket(), newPath, om);
            initResponse = connector.getClient().initiateMultipartUpload(initRequest);

            long contentLength = file.length();
            long partSize = 5242880; // Set part size to 5 MB.
            // Step 2: Upload parts.
            long filePosition = 0;
            for (int i = 1; filePosition < contentLength; i++) {
                // Last part can be less than 5 MB. Adjust part size.
                partSize = Math.min(partSize, (contentLength - filePosition));

                // Create request to upload a part.
                UploadPartRequest uploadRequest = new UploadPartRequest()
                        .withBucketName(connector.getBucket()).withKey(newPath)
                        .withUploadId(initResponse.getUploadId()).withPartNumber(i)
                        .withFileOffset(filePosition)
                        .withFile(file)
                        .withPartSize(partSize);

                // Upload part and add response to our list.
                partETags.add(connector.getClient().uploadPart(uploadRequest).getPartETag());

                filePosition += partSize;
            }

            // Step 3: Complete.
            CompleteMultipartUploadRequest compRequest = new
                    CompleteMultipartUploadRequest(
                    connector.getBucket(),
                    newPath,
                    initResponse.getUploadId(),
                    partETags);

            connector.getClient().completeMultipartUpload(compRequest);
        } catch (Throwable e) {
            LOG.error(e.getMessage(), e);
            if (initResponse != null) {
                connector.getClient().abortMultipartUpload(new AbortMultipartUploadRequest(
                        connector.getBucket(), newPath, initResponse.getUploadId()));
            }
        }
    }
}