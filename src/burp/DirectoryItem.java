package burp;

public class DirectoryItem {
        private String fullPath;
        private String name;

        public DirectoryItem(String fullPath, String name) {
            this.fullPath = fullPath;
            this.name = name;
        }

        public String getFullPath() {
            return fullPath;
        }

        public String getName() {
            return name;
        }

        @Override
        public String toString() {
            return name;
        }
}