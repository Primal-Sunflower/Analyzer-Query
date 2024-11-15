package cn.edu.query.qvog.query.arkts.CWE.CWE_434;

public class UnrestrictedFileUpload extends ArkTSQuery {
    public static void main(String[] args) {
        QueryEngine.getInstance().execute(new UnrestrictedFileUpload()).close();
    }

    @Override
    public String getQueryName() {
        return "CWE-434: Unrestricted File Upload";
    }

    @Override
    public CompleteQuery run() {
        return QueryDescriptor.open()
                // Step 1: 检测文件上传函数
                .from("upload", new ContainsFunctionCall("uploadFile"), "uploadFile")

                // Step 2: 查找文件类型验证 (检查是否有对文件类型的验证)
                .fromP("validation", new ContainsFunctionCall("mimeType").or(new ContainsFunctionCall("checkFileType")))

                // Step 3: 跟踪从上传到验证的流程
                .where(TaintFlowPredicate.with()
                        .source("upload")
                        .sink("validation")
                        .as("path").negate().exists()) // 如果没有找到验证，返回漏洞

                // Step 4: 选择查询结果
                .select("upload", "path");
    }
}
