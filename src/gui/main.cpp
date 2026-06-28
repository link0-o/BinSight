#include <binsight/config.hpp>
#include <binsight/dynamic_observer.hpp>
#include <binsight/llm_client.hpp>
#include <binsight/scan_pipeline.hpp>
#include <binsight/types.hpp>
#include <binsight/utils.hpp>

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDesktopServices>
#include <QDir>
#include <QDragEnterEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMainWindow>
#include <QMessageBox>
#include <QMetaObject>
#include <QMimeData>
#include <QPointer>
#include <QPushButton>
#include <QSpinBox>
#include <QStandardPaths>
#include <QTabWidget>
#include <QTextEdit>
#include <QUrl>
#include <QVBoxLayout>

#include <exception>
#include <filesystem>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#endif

namespace {

enum class UiLanguage { English, Chinese };

std::filesystem::path path_from_qstring(const QString& value) {
#ifdef _WIN32
  return std::filesystem::path(value.toStdWString());
#else
  return std::filesystem::path(value.toStdString());
#endif
}

QString qstring_from_path(const std::filesystem::path& path) {
#ifdef _WIN32
  return QString::fromStdWString(path.wstring());
#else
  return QString::fromStdString(path.string());
#endif
}

QString app_dir() {
  return QApplication::applicationDirPath();
}

#ifdef _WIN32
bool current_process_elevated() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return false;
  }
  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
  CloseHandle(token);
  return ok && elevation.TokenIsElevated != 0;
}

std::wstring quote_windows_arg(const std::wstring& value) {
  std::wstring out = L"\"";
  for (wchar_t c : value) {
    if (c == L'"') {
      out += L"\\\"";
    } else {
      out.push_back(c);
    }
  }
  out.push_back(L'"');
  return out;
}

bool run_windows_etw_observer_elevated(const std::filesystem::path& exe_dir,
                                       const binsight::WindowsEtwObserveOptions& observe,
                                       std::vector<std::string>& warnings) {
  const auto cli_path = exe_dir / "binsight.exe";
  std::wostringstream params;
  params << L"observe windows-etw " << quote_windows_arg(observe.binary_path.wstring())
         << L" --out " << quote_windows_arg(observe.output_path.wstring())
         << L" --i-understand-risk"
         << L" --timeout " << observe.timeout_seconds
         << L" --network " << QString::fromStdString(observe.network_mode).toStdWString();

  SHELLEXECUTEINFOW info{};
  info.cbSize = sizeof(info);
  info.fMask = SEE_MASK_NOCLOSEPROCESS;
  info.lpVerb = L"runas";
  const auto file = cli_path.wstring();
  const auto parameters = params.str();
  const auto directory = exe_dir.wstring();
  info.lpFile = file.c_str();
  info.lpParameters = parameters.c_str();
  info.lpDirectory = directory.c_str();
  info.nShow = SW_SHOWNORMAL;
  if (!ShellExecuteExW(&info)) {
    const DWORD error = GetLastError();
    if (error == ERROR_CANCELLED) {
      warnings.push_back("windows_etw_elevation_cancelled: user cancelled the UAC prompt");
    } else {
      warnings.push_back("windows_etw_elevation_failed: ShellExecuteExW error " +
                         std::to_string(error));
    }
    return false;
  }

  WaitForSingleObject(info.hProcess, INFINITE);
  DWORD exit_code = 0;
  if (GetExitCodeProcess(info.hProcess, &exit_code) && exit_code != 0) {
    warnings.push_back("windows_etw_elevated_observer_exit_code: " + std::to_string(exit_code));
  }
  CloseHandle(info.hProcess);
  if (!std::filesystem::exists(observe.output_path)) {
    warnings.push_back("windows_etw_elevated_observer_failed: dynamic report was not written");
    return false;
  }
  warnings.push_back("windows_etw_elevated_observation_completed");
  return true;
}
#endif

std::string provider_value(const QString& preset) {
  if (preset == "OpenAI (Responses)") {
    return "responses";
  }
  if (preset == "DeepSeek (OpenAI)" || preset == "OpenAI-compatible" ||
      preset == "Kimi / Moonshot" || preset == "GLM / Zhipu" ||
      preset == "Qwen / DashScope" || preset == "SiliconFlow" ||
      preset == "OpenRouter") {
    return "openai";
  }
  if (preset == "DeepSeek (Anthropic)" || preset == "Anthropic") {
    return "anthropic";
  }
  if (preset == "Ollama") {
    return "ollama";
  }
  return "none";
}

std::string default_key_name(const QString& preset) {
  if (preset == "DeepSeek (OpenAI)" || preset == "DeepSeek (Anthropic)") {
    return "binsight:deepseek";
  }
  if (preset == "Kimi / Moonshot") return "binsight:kimi";
  if (preset == "GLM / Zhipu") return "binsight:glm";
  if (preset == "Qwen / DashScope") return "binsight:qwen";
  if (preset == "SiliconFlow") return "binsight:siliconflow";
  if (preset == "OpenRouter") return "binsight:openrouter";
  if (preset == "Anthropic") return "binsight:anthropic";
  if (preset == "OpenAI (Responses)" || preset == "OpenAI-compatible") {
    return "binsight:openai";
  }
  if (preset == "Ollama") {
    return "binsight:ollama";
  }
  return {};
}

std::string default_key_env(const QString& preset) {
  if (preset == "DeepSeek (OpenAI)" || preset == "DeepSeek (Anthropic)") {
    return "DEEPSEEK_API_KEY";
  }
  if (preset == "Kimi / Moonshot") return "MOONSHOT_API_KEY";
  if (preset == "GLM / Zhipu") return "ZHIPU_API_KEY";
  if (preset == "Qwen / DashScope") return "DASHSCOPE_API_KEY";
  if (preset == "SiliconFlow") return "SILICONFLOW_API_KEY";
  if (preset == "OpenRouter") return "OPENROUTER_API_KEY";
  if (preset == "Anthropic") return "ANTHROPIC_API_KEY";
  if (preset == "OpenAI (Responses)" || preset == "OpenAI-compatible") {
    return "OPENAI_API_KEY";
  }
  return "OPENAI_API_KEY";
}

class DropLabel final : public QLabel {
 public:
  explicit DropLabel(QWidget* parent = nullptr) : QLabel(parent) {
    setAcceptDrops(true);
    setAlignment(Qt::AlignCenter);
    setMinimumHeight(92);
    setText("Drop a binary here or choose a file");
    setStyleSheet("QLabel { border: 2px dashed #6b7280; border-radius: 8px; color: #374151; }");
  }

  void set_on_file(std::function<void(QString)> callback) {
    on_file_ = std::move(callback);
  }

 protected:
  void dragEnterEvent(QDragEnterEvent* event) override {
    if (event->mimeData()->hasUrls()) {
      event->acceptProposedAction();
    }
  }

  void dropEvent(QDropEvent* event) override {
    const auto urls = event->mimeData()->urls();
    if (!urls.empty() && urls.front().isLocalFile() && on_file_) {
      on_file_(urls.front().toLocalFile());
      event->acceptProposedAction();
    }
  }

 private:
  std::function<void(QString)> on_file_;
};

class MainWindow final : public QMainWindow {
 public:
  MainWindow() {
    setWindowTitle("BinSight");
    resize(980, 720);
    build_ui();
    load_config();
    apply_ui_language();
  }

  void set_initial_file(const QString& file) {
    set_binary_path(file);
  }

 private:
  QLabel* add_form_row(QFormLayout* form, QWidget* field) {
    auto* label = new QLabel(form->parentWidget());
    form->addRow(label, field);
    return label;
  }

  void build_ui() {
    auto* tabs = new QTabWidget(this);
    setCentralWidget(tabs);

    auto* scan_page = new QWidget(this);
    auto* scan_layout = new QVBoxLayout(scan_page);

    drop_label_ = new DropLabel(scan_page);
    drop_label_->set_on_file([this](const QString& file) { set_binary_path(file); });
    scan_layout->addWidget(drop_label_);

    auto* file_row = new QHBoxLayout();
    file_path_ = new QLineEdit(scan_page);
    browse_file_ = new QPushButton(scan_page);
    file_row->addWidget(file_path_, 1);
    file_row->addWidget(browse_file_);
    scan_layout->addLayout(file_row);
    connect(browse_file_, &QPushButton::clicked, this, [this]() {
      const QString file = QFileDialog::getOpenFileName(this, tr_text("choose_binary"));
      if (!file.isEmpty()) {
        set_binary_path(file);
      }
    });

    auto* output_row = new QHBoxLayout();
    output_dir_ = new QLineEdit(scan_page);
    output_dir_->setText(default_output_dir());
    browse_output_ = new QPushButton(scan_page);
    output_row->addWidget(output_dir_, 1);
    output_row->addWidget(browse_output_);
    scan_layout->addLayout(output_row);
    connect(browse_output_, &QPushButton::clicked, this, [this]() {
      const QString dir = QFileDialog::getExistingDirectory(this, tr_text("choose_output_dir"), output_dir_->text());
      if (!dir.isEmpty()) {
        output_dir_->setText(dir);
      }
    });

    mode_group_ = new QGroupBox(scan_page);
    auto* mode_form = new QFormLayout(mode_group_);
    ui_language_ = new QComboBox(mode_group_);
    ui_language_->addItem("English", "en");
    ui_language_->addItem("中文", "zh-CN");
    if (QLocale::system().language() == QLocale::Chinese) {
      ui_language_->setCurrentIndex(1);
    }
    ui_language_label_ = add_form_row(mode_form, ui_language_);
    report_language_ = new QComboBox(mode_group_);
    report_language_->addItems({"both", "zh-CN", "en"});
    report_language_label_ = add_form_row(mode_form, report_language_);

    dynamic_accept_ = new QCheckBox("I understand Docker is not a malware-grade sandbox", mode_group_);
    dynamic_timeout_ = new QSpinBox(mode_group_);
    dynamic_timeout_->setRange(5, 600);
#ifdef _WIN32
    dynamic_timeout_->setValue(90);
    dynamic_image_ = new QLineEdit("Windows ETW native", mode_group_);
#else
    dynamic_timeout_->setValue(30);
    dynamic_image_ = new QLineEdit("binsight-observer:latest", mode_group_);
#endif
    dynamic_network_ = new QComboBox(mode_group_);
#ifdef _WIN32
    dynamic_network_->addItems({"observe", "off"});
    dynamic_image_->setEnabled(false);
#else
    dynamic_network_->addItems({"none", "bridge"});
#endif
    docker_risk_label_ = add_form_row(mode_form, dynamic_accept_);
    docker_image_label_ = add_form_row(mode_form, dynamic_image_);
    timeout_label_ = add_form_row(mode_form, dynamic_timeout_);
    network_label_ = add_form_row(mode_form, dynamic_network_);
    scan_layout->addWidget(mode_group_);

    auto* actions = new QHBoxLayout();
    scan_button_ = new QPushButton(scan_page);
    dynamic_button_ = new QPushButton(scan_page);
    actions->addWidget(scan_button_);
    actions->addWidget(dynamic_button_);
    actions->addStretch(1);
    scan_layout->addLayout(actions);
    connect(scan_button_, &QPushButton::clicked, this, [this]() { run_scan(false); });
    connect(dynamic_button_, &QPushButton::clicked, this, [this]() { run_scan(true); });

    result_text_ = new QTextEdit(scan_page);
    result_text_->setReadOnly(true);
    scan_layout->addWidget(result_text_, 1);

    auto* report_buttons = new QHBoxLayout();
    open_zh_ = new QPushButton(scan_page);
    open_en_ = new QPushButton(scan_page);
    open_json_ = new QPushButton(scan_page);
    open_dir_ = new QPushButton(scan_page);
    report_buttons->addWidget(open_zh_);
    report_buttons->addWidget(open_en_);
    report_buttons->addWidget(open_json_);
    report_buttons->addWidget(open_dir_);
    report_buttons->addStretch(1);
    scan_layout->addLayout(report_buttons);
    connect(open_zh_, &QPushButton::clicked, this, [this]() { open_file(last_zh_report_); });
    connect(open_en_, &QPushButton::clicked, this, [this]() { open_file(last_en_report_); });
    connect(open_json_, &QPushButton::clicked, this, [this]() { open_file(last_json_report_); });
    connect(open_dir_, &QPushButton::clicked, this, [this]() { open_file(path_from_qstring(output_dir_->text())); });

    auto* config_page = new QWidget(this);
    auto* config_layout = new QVBoxLayout(config_page);
    config_group_ = new QGroupBox(config_page);
    auto* config_form = new QFormLayout(config_group_);
    provider_ = new QComboBox(config_group_);
    provider_->addItems({"none", "DeepSeek (OpenAI)", "DeepSeek (Anthropic)",
                         "Kimi / Moonshot", "GLM / Zhipu", "Qwen / DashScope",
                         "SiliconFlow", "OpenRouter", "OpenAI (Responses)",
                         "OpenAI-compatible",
                         "Anthropic", "Ollama"});
    base_url_ = new QLineEdit(config_group_);
    model_ = new QComboBox(config_group_);
    model_->setEditable(false);
    custom_model_ = new QLineEdit(config_group_);
    llm_timeout_ = new QSpinBox(config_group_);
    llm_timeout_->setRange(5, 600);
    llm_timeout_->setValue(90);
    llm_timeout_->setSuffix(" s");
    api_key_ = new QLineEdit(config_group_);
    api_key_->setEchoMode(QLineEdit::Password);
    provider_label_ = add_form_row(config_form, provider_);
    base_url_label_ = add_form_row(config_form, base_url_);
    model_label_ = add_form_row(config_form, model_);
    custom_model_label_ = add_form_row(config_form, custom_model_);
    llm_timeout_label_ = add_form_row(config_form, llm_timeout_);
    api_key_label_ = add_form_row(config_form, api_key_);
    config_layout->addWidget(config_group_);

    auto* config_actions = new QHBoxLayout();
    save_config_ = new QPushButton(config_page);
    save_key_ = new QPushButton(config_page);
    test_connection_ = new QPushButton(config_page);
    show_config_ = new QPushButton(config_page);
    config_actions->addWidget(save_config_);
    config_actions->addWidget(save_key_);
    config_actions->addWidget(test_connection_);
    config_actions->addWidget(show_config_);
    config_actions->addStretch(1);
    config_layout->addLayout(config_actions);
    config_layout->addStretch(1);

    connect(provider_, &QComboBox::currentTextChanged, this, [this](const QString& value) {
      apply_provider_preset(value);
    });
    connect(ui_language_, &QComboBox::currentIndexChanged, this, [this]() { apply_ui_language(); });
    connect(save_config_, &QPushButton::clicked, this, [this]() { save_non_sensitive_config(); });
    connect(save_key_, &QPushButton::clicked, this, [this]() { save_api_key(); });
    connect(test_connection_, &QPushButton::clicked, this, [this]() { test_llm_connection(); });
    connect(show_config_, &QPushButton::clicked, this, [this]() {
      binsight::ConfigManager manager;
      QMessageBox::information(this, tr_text("config_title"), qstring_from_path(manager.config_path()));
    });

    tabs_ = tabs;
    scan_page_ = scan_page;
    config_page_ = config_page;
    tabs_->addTab(scan_page_, "");
    tabs_->addTab(config_page_, "");
    apply_provider_preset(provider_->currentText());
  }

  UiLanguage ui_language() const {
    if (ui_language_ != nullptr && ui_language_->currentData().toString() == "zh-CN") {
      return UiLanguage::Chinese;
    }
    return UiLanguage::English;
  }

  QString tr_text(const char* key) const {
    const bool zh = ui_language() == UiLanguage::Chinese;
    const std::string name = key;
    if (name == "drop_prompt") return zh ? "拖拽可执行文件到这里，或点击选择文件" : "Drop a binary here or choose a file";
    if (name == "drop_admin_prompt") return zh ? "管理员模式无法接收普通资源管理器拖拽；请使用选择文件或粘贴路径" : "Administrator mode cannot receive drops from normal Explorer; choose a file or paste a path";
    if (name == "choose_file") return zh ? "选择文件" : "Choose File";
    if (name == "choose_binary") return zh ? "选择二进制文件" : "Choose binary";
    if (name == "output_dir") return zh ? "输出目录" : "Output Directory";
    if (name == "choose_output_dir") return zh ? "选择输出目录" : "Choose output directory";
    if (name == "analysis") return zh ? "分析" : "Analysis";
    if (name == "ui_language") return zh ? "界面语言" : "Interface language";
    if (name == "report_language") return zh ? "报告语言" : "Report language";
    if (name == "docker_risk") return zh ? "Docker 风险确认" : "Docker risk";
    if (name == "docker_accept") return zh ? "我理解 Docker 不是恶意软件级沙箱" : "I understand Docker is not a malware-grade sandbox";
    if (name == "windows_etw_risk") return zh ? "Windows 专家风险确认" : "Windows expert risk";
    if (name == "windows_etw_accept") return zh ? "我理解目标会在本机真实运行，BinSight 不是沙箱" : "I understand the target runs on this host and BinSight is not a sandbox";
    if (name == "docker_unavailable_windows") return zh ? "Windows 不支持 Linux Docker 动态观测" : "Linux Docker observation is not available on Windows";
    if (name == "docker_image") return zh ? "Docker 镜像" : "Docker image";
    if (name == "windows_etw_backend") return zh ? "Windows 观测后端" : "Windows backend";
    if (name == "timeout_seconds") return zh ? "超时秒数" : "Timeout seconds";
    if (name == "network") return zh ? "网络" : "Network";
    if (name == "run_static") return zh ? "运行静态扫描" : "Run Static Scan";
    if (name == "run_dynamic") return zh ? "运行 Docker 动态观测 + 扫描" : "Run Docker Observation + Scan";
    if (name == "run_windows_etw") return zh ? "运行 Windows ETW 专家观测 + 扫描" : "Run Windows ETW Expert Observation + Scan";
    if (name == "open_zh") return zh ? "打开中文报告" : "Open Chinese Report";
    if (name == "open_en") return zh ? "打开英文报告" : "Open English Report";
    if (name == "open_json") return zh ? "打开 JSON" : "Open JSON";
    if (name == "open_output") return zh ? "打开输出目录" : "Open Output Directory";
    if (name == "ai_provider") return zh ? "AI 配置" : "AI Provider";
    if (name == "provider") return zh ? "Provider" : "Provider";
    if (name == "base_url") return zh ? "Base URL" : "Base URL";
    if (name == "model") return zh ? "模型" : "Model";
    if (name == "custom_model") return zh ? "自定义模型名" : "Custom model";
    if (name == "custom_model_placeholder") return zh ? "可选：输入后优先使用这个模型名" : "Optional: overrides the preset model";
    if (name == "llm_timeout") return zh ? "AI 超时秒数" : "AI timeout seconds";
    if (name == "api_key") return zh ? "API key" : "API key";
    if (name == "api_key_placeholder") return zh ? "仅在安全凭据库可用时保存" : "Only saved to secure credential storage when available";
    if (name == "save_config") return zh ? "保存配置" : "Save Config";
    if (name == "save_key") return zh ? "安全保存 API Key" : "Save API Key Securely";
    if (name == "test_connection") return zh ? "测试模型联通" : "Test Model";
    if (name == "show_config") return zh ? "显示配置路径" : "Show Config Path";
    if (name == "scan_tab") return zh ? "扫描" : "Scan";
    if (name == "config_tab") return zh ? "AI 配置" : "AI Config";
    if (name == "saved_title") return zh ? "已保存" : "Saved";
    if (name == "saved_config") return zh ? "非敏感配置已保存。" : "Non-sensitive config was saved.";
    if (name == "save_failed") return zh ? "保存失败" : "Save failed";
    if (name == "api_key_title") return zh ? "API key" : "API key";
    if (name == "api_key_missing") return zh ? "请先选择 Provider 并输入 API key。" : "Choose a provider and enter an API key first.";
    if (name == "secure_unavailable") return zh ? "当前构建无法使用安全凭据库。请改用环境变量。" : "Secure credential storage is unavailable in this build. Use an environment variable instead.";
    if (name == "api_key_saved") return zh ? "API key 已保存到系统安全凭据库。" : "API key was saved to secure credential storage.";
    if (name == "test_title") return zh ? "模型联通测试" : "Model connection test";
    if (name == "testing_model") return zh ? "正在测试模型联通，慢模型可能需要几十秒..." : "Testing model connection; slow models may take tens of seconds...";
    if (name == "scan_title") return zh ? "扫描" : "Scan";
    if (name == "choose_binary_first") return zh ? "请先选择一个二进制文件。" : "Choose a binary first.";
    if (name == "dynamic_title") return zh ? "动态观测" : "Dynamic observation";
    if (name == "confirm_docker") return zh ? "运行动态观测前必须确认 Docker 风险提示。" : "Confirm the Docker risk notice before running dynamic observation.";
    if (name == "confirm_windows_etw") return zh ? "运行 Windows 专家观测前必须确认本机执行风险。" : "Confirm the local execution risk before running Windows expert observation.";
    if (name == "elevation_title") return zh ? "需要管理员权限" : "Administrator permission required";
    if (name == "elevation_prompt") return zh ? "目标程序需要管理员权限才能启动。BinSight 将只以管理员权限运行一次动态观测子进程，GUI 仍保持普通权限。是否继续？" : "The target requires administrator privileges to start. BinSight will elevate only one observation subprocess; the GUI remains non-admin. Continue?";
    if (name == "running_dynamic") return zh ? "正在运行 Docker 动态观测和扫描..." : "Running Docker observation and scan...";
    if (name == "running_windows_etw") return zh ? "正在运行 Windows ETW 专家观测和扫描..." : "Running Windows ETW expert observation and scan...";
    if (name == "running_static") return zh ? "正在运行静态扫描..." : "Running static scan...";
    if (name == "open_title") return zh ? "打开" : "Open";
    if (name == "no_file") return zh ? "还没有可打开的文件。" : "No file is available yet.";
    if (name == "config_title") return zh ? "BinSight 配置" : "BinSight config";
    return QString::fromUtf8(key);
  }

  void apply_ui_language() {
    setWindowTitle("BinSight");
#ifdef _WIN32
    const bool elevated = current_process_elevated();
    drop_label_->setAcceptDrops(!elevated);
    drop_label_->setToolTip(elevated ? tr_text("drop_admin_prompt") : QString());
#endif
    if (file_path_ != nullptr && file_path_->text().isEmpty()) {
#ifdef _WIN32
      drop_label_->setText(current_process_elevated() ? tr_text("drop_admin_prompt") : tr_text("drop_prompt"));
#else
      drop_label_->setText(tr_text("drop_prompt"));
#endif
    }
    browse_file_->setText(tr_text("choose_file"));
    browse_output_->setText(tr_text("output_dir"));
    mode_group_->setTitle(tr_text("analysis"));
    ui_language_label_->setText(tr_text("ui_language"));
    report_language_label_->setText(tr_text("report_language"));
#ifdef _WIN32
    docker_risk_label_->setText(tr_text("windows_etw_risk"));
    dynamic_accept_->setText(tr_text("windows_etw_accept"));
    docker_image_label_->setText(tr_text("windows_etw_backend"));
    dynamic_button_->setText(tr_text("run_windows_etw"));
#else
    docker_risk_label_->setText(tr_text("docker_risk"));
    dynamic_accept_->setText(tr_text("docker_accept"));
    docker_image_label_->setText(tr_text("docker_image"));
    dynamic_button_->setText(tr_text("run_dynamic"));
#endif
    timeout_label_->setText(tr_text("timeout_seconds"));
    network_label_->setText(tr_text("network"));
    scan_button_->setText(tr_text("run_static"));
    open_zh_->setText(tr_text("open_zh"));
    open_en_->setText(tr_text("open_en"));
    open_json_->setText(tr_text("open_json"));
    open_dir_->setText(tr_text("open_output"));
    config_group_->setTitle(tr_text("ai_provider"));
    provider_label_->setText(tr_text("provider"));
    base_url_label_->setText(tr_text("base_url"));
    model_label_->setText(tr_text("model"));
    custom_model_label_->setText(tr_text("custom_model"));
    custom_model_->setPlaceholderText(tr_text("custom_model_placeholder"));
    llm_timeout_label_->setText(tr_text("llm_timeout"));
    api_key_label_->setText(tr_text("api_key"));
    api_key_->setPlaceholderText(tr_text("api_key_placeholder"));
    save_config_->setText(tr_text("save_config"));
    save_key_->setText(tr_text("save_key"));
    test_connection_->setText(tr_text("test_connection"));
    show_config_->setText(tr_text("show_config"));
    tabs_->setTabText(tabs_->indexOf(scan_page_), tr_text("scan_tab"));
    tabs_->setTabText(tabs_->indexOf(config_page_), tr_text("config_tab"));
  }

  QString default_output_dir() const {
    const QString docs = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (!docs.isEmpty()) {
      return QDir(docs).filePath("BinSight");
    }
    return QDir::currentPath();
  }

  void set_binary_path(const QString& file) {
    file_path_->setText(file);
    drop_label_->setText(QFileInfo(file).fileName());
  }

  void apply_provider_preset(const QString& preset) {
    model_->clear();
    if (preset == "DeepSeek (OpenAI)") {
      base_url_->setText("https://api.deepseek.com");
      model_->addItems({"deepseek-v4-flash", "deepseek-v4-pro"});
      model_->setCurrentText("deepseek-v4-flash");
    } else if (preset == "DeepSeek (Anthropic)") {
      base_url_->setText("https://api.deepseek.com/anthropic");
      model_->addItems({"deepseek-v4-flash", "deepseek-v4-pro"});
      model_->setCurrentText("deepseek-v4-pro");
    } else if (preset == "Kimi / Moonshot") {
      base_url_->setText("https://api.moonshot.cn/v1");
      model_->addItems({"kimi-latest", "kimi-k2-0711-preview", "moonshot-v1-8k", "moonshot-v1-32k"});
      model_->setCurrentText("kimi-latest");
    } else if (preset == "GLM / Zhipu") {
      base_url_->setText("https://open.bigmodel.cn/api/paas/v4");
      model_->addItems({"glm-5.2", "glm-4.5", "glm-4.5-air", "glm-4-plus"});
      model_->setCurrentText("glm-5.2");
    } else if (preset == "Qwen / DashScope") {
      base_url_->setText("https://dashscope.aliyuncs.com/compatible-mode/v1");
      model_->addItems({"qwen-plus", "qwen-max", "qwen-turbo", "qwen-long"});
      model_->setCurrentText("qwen-plus");
    } else if (preset == "SiliconFlow") {
      base_url_->setText("https://api.siliconflow.cn/v1");
      model_->addItems({"deepseek-ai/DeepSeek-V3", "Qwen/Qwen2.5-72B-Instruct", "THUDM/glm-4-9b-chat"});
      model_->setCurrentText("deepseek-ai/DeepSeek-V3");
    } else if (preset == "OpenRouter") {
      base_url_->setText("https://openrouter.ai/api/v1");
      model_->addItems({"openai/gpt-4o-mini", "anthropic/claude-3.5-sonnet", "google/gemini-flash-1.5"});
      model_->setCurrentText("openai/gpt-4o-mini");
    } else if (preset == "OpenAI (Responses)") {
      base_url_->setText("https://api.openai.com/v1");
      model_->addItems({"gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5.4-nano"});
      model_->setCurrentText("gpt-5.5");
    } else if (preset == "OpenAI-compatible") {
      base_url_->setText("https://api.openai.com/v1");
      model_->addItems({"gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "gpt-5.4-nano"});
      model_->setCurrentText("gpt-5.5");
    } else if (preset == "Anthropic") {
      base_url_->setText("https://api.anthropic.com");
      model_->addItems({"claude-3-5-sonnet-latest", "claude-3-5-haiku-latest"});
      model_->setCurrentText("claude-3-5-sonnet-latest");
    } else if (preset == "Ollama") {
      base_url_->setText("http://localhost:11434");
      model_->addItems({"llama3.1", "qwen2.5", "mistral"});
      model_->setCurrentText("llama3.1");
    } else {
      base_url_->clear();
      model_->setEditText("");
    }
  }

  binsight::ReportLanguage selected_language() const {
    return binsight::report_language_from_string(report_language_->currentText().toStdString());
  }

  binsight::ScanOptions scan_options() const {
    binsight::ScanOptions options;
    options.binary_path = path_from_qstring(file_path_->text());
    options.output_dir = path_from_qstring(output_dir_->text());
    options.markdown_out = "report.md";
    options.json_out = "report.json";
    options.report_language = selected_language();
    options.provider = provider_value(provider_->currentText());
    options.base_url = base_url_->text().toStdString();
    options.model = custom_model_->text().trimmed().isEmpty()
                        ? model_->currentText().toStdString()
                        : custom_model_->text().trimmed().toStdString();
    options.api_key_env = default_key_env(provider_->currentText());
    options.api_key_name = default_key_name(provider_->currentText());
    options.api_key_override = api_key_->text().toStdString();
    options.llm_timeout_seconds = llm_timeout_->value();
    return options;
  }

  void load_config() {
    std::vector<std::string> warnings;
    binsight::ConfigManager manager;
    const auto config = manager.load(warnings);
    if (!config) {
      return;
    }
    output_dir_->setText(qstring_from_path(config->output_dir.empty() ? path_from_qstring(default_output_dir())
                                                                      : config->output_dir));
    report_language_->setCurrentText(QString::fromStdString(binsight::to_string(config->report_language)));
    llm_timeout_->setValue(config->llm_timeout_seconds);
    if (config->provider == "ollama") {
      provider_->setCurrentText("Ollama");
    } else if (config->api_key_name == "binsight:deepseek" && config->provider == "anthropic") {
      provider_->setCurrentText("DeepSeek (Anthropic)");
    } else if (config->api_key_name == "binsight:deepseek" ||
               config->base_url.find("deepseek") != std::string::npos) {
      provider_->setCurrentText("DeepSeek (OpenAI)");
    } else if (config->api_key_name == "binsight:kimi" ||
               config->base_url.find("moonshot") != std::string::npos) {
      provider_->setCurrentText("Kimi / Moonshot");
    } else if (config->api_key_name == "binsight:glm" ||
               config->base_url.find("bigmodel") != std::string::npos) {
      provider_->setCurrentText("GLM / Zhipu");
    } else if (config->api_key_name == "binsight:qwen" ||
               config->base_url.find("dashscope") != std::string::npos) {
      provider_->setCurrentText("Qwen / DashScope");
    } else if (config->api_key_name == "binsight:siliconflow" ||
               config->base_url.find("siliconflow") != std::string::npos) {
      provider_->setCurrentText("SiliconFlow");
    } else if (config->api_key_name == "binsight:openrouter" ||
               config->base_url.find("openrouter") != std::string::npos) {
      provider_->setCurrentText("OpenRouter");
    } else if (config->provider == "anthropic") {
      provider_->setCurrentText("Anthropic");
    } else if (config->provider == "responses") {
      provider_->setCurrentText("OpenAI (Responses)");
    } else if (config->provider == "openai") {
      provider_->setCurrentText("OpenAI-compatible");
    } else {
      provider_->setCurrentText("none");
    }
    base_url_->setText(QString::fromStdString(config->base_url));
    const QString configured_model = QString::fromStdString(config->model);
    const int preset_index = model_->findText(configured_model);
    if (preset_index >= 0) {
      model_->setCurrentIndex(preset_index);
      custom_model_->clear();
    } else {
      custom_model_->setText(configured_model);
    }
  }

  binsight::AppConfig app_config_from_ui() const {
    binsight::AppConfig config;
    config.provider = provider_value(provider_->currentText());
    config.base_url = base_url_->text().toStdString();
    config.model = custom_model_->text().trimmed().isEmpty()
                       ? model_->currentText().toStdString()
                       : custom_model_->text().trimmed().toStdString();
    config.api_key_env = default_key_env(provider_->currentText());
    config.api_key_name = default_key_name(provider_->currentText());
    config.report_language = selected_language();
    config.output_dir = path_from_qstring(output_dir_->text());
    config.llm_timeout_seconds = llm_timeout_->value();
    return config;
  }

  void save_non_sensitive_config() {
    try {
      binsight::ConfigManager manager;
      manager.save(app_config_from_ui());
      QMessageBox::information(this, tr_text("saved_title"), tr_text("saved_config"));
    } catch (const std::exception& ex) {
      QMessageBox::critical(this, tr_text("save_failed"), ex.what());
    }
  }

  void save_api_key() {
    const std::string secret = api_key_->text().toStdString();
    const std::string name = default_key_name(provider_->currentText());
    if (secret.empty() || name.empty()) {
      QMessageBox::warning(this, tr_text("api_key_title"), tr_text("api_key_missing"));
      return;
    }
    binsight::CredentialStore store;
    if (!store.is_secure_store_available()) {
      QMessageBox::warning(this, tr_text("api_key_title"), tr_text("secure_unavailable"));
      return;
    }
    std::string error;
    if (!store.store(name, secret, error)) {
      QMessageBox::critical(this, tr_text("api_key_title"), QString::fromStdString(error));
      return;
    }
    api_key_->clear();
    save_non_sensitive_config();
    QMessageBox::information(this, tr_text("api_key_title"), tr_text("api_key_saved"));
  }

  void test_llm_connection() {
    auto options = scan_options();
    result_text_->setPlainText(tr_text("testing_model"));
    test_connection_->setEnabled(false);
    QPointer<MainWindow> self(this);
    const bool use_chinese = ui_language() == UiLanguage::Chinese;
    std::thread([self, options, use_chinese]() {
      std::vector<std::string> warnings;
      binsight::LlmClient client{binsight::ProcessRunner{}};
      const auto result = client.test_connection(options, warnings);
      std::ostringstream out;
      out << (use_chinese ? "Provider: " : "Provider: ") << options.provider << "\n";
      out << (use_chinese ? "Base URL: " : "Base URL: ") << options.base_url << "\n";
      out << (use_chinese ? "模型: " : "Model: ") << options.model << "\n";
      out << (use_chinese ? "超时秒数: " : "Timeout seconds: ") << options.llm_timeout_seconds << "\n";
      out << (use_chinese ? "结果: " : "Result: ") << (result.ok ? "ok" : "failed") << "\n";
      out << result.message << "\n";
      for (const auto& warning : warnings) {
        if (warning != result.message) {
          out << (use_chinese ? "警告: " : "Warning: ") << warning << "\n";
        }
      }
      const QString message = QString::fromStdString(out.str());
      QMetaObject::invokeMethod(qApp, [self, message, ok = result.ok]() {
        if (!self) {
          return;
        }
        self->test_connection_->setEnabled(true);
        self->result_text_->setPlainText(message);
        QMessageBox::information(self, self->tr_text("test_title"), message);
        (void)ok;
      }, Qt::QueuedConnection);
    }).detach();
  }

  void run_scan(bool with_dynamic) {
    if (file_path_->text().isEmpty()) {
      QMessageBox::warning(this, tr_text("scan_title"), tr_text("choose_binary_first"));
      return;
    }
    if (with_dynamic && !dynamic_accept_->isChecked()) {
#ifdef _WIN32
      QMessageBox::warning(this, tr_text("dynamic_title"), tr_text("confirm_windows_etw"));
#else
      QMessageBox::warning(this, tr_text("dynamic_title"), tr_text("confirm_docker"));
#endif
      return;
    }

    set_running(true);
    result_text_->setPlainText(
        with_dynamic
#ifdef _WIN32
            ? tr_text("running_windows_etw")
#else
            ? tr_text("running_dynamic")
#endif
            : tr_text("running_static"));
    auto options = scan_options();
    const auto exe_dir = path_from_qstring(app_dir());
    const auto docker_image = dynamic_image_->text().toStdString();
    const auto docker_network = dynamic_network_->currentText().toStdString();
    const int timeout = dynamic_timeout_->value();

    QPointer<MainWindow> self(this);
    const bool use_chinese = ui_language() == UiLanguage::Chinese;
    std::thread([self, options, exe_dir, with_dynamic, docker_image, docker_network, timeout, use_chinese]() mutable {
      QString message;
      bool ok = true;
      binsight::ScanExecutionResult result;
      try {
        std::vector<std::string> warnings;
        if (with_dynamic) {
#ifdef _WIN32
          binsight::WindowsEtwObserveOptions observe;
          observe.binary_path = options.binary_path;
          observe.output_path = binsight::with_output_dir(options.output_dir, "dynamic.json");
          observe.network_mode = docker_network;
          observe.timeout_seconds = timeout;
          observe.risk_accepted = true;
          binsight::WindowsEtwObserver observer;
          const auto dynamic = observer.observe(observe, warnings);
          if (dynamic.failure_reason == "requires_elevation") {
            bool allow_elevation = false;
            QMetaObject::invokeMethod(qApp, [self, use_chinese, &allow_elevation]() {
              if (!self) {
                return;
              }
              const auto answer = QMessageBox::question(
                  self,
                  self->tr_text("elevation_title"),
                  self->tr_text("elevation_prompt"),
                  QMessageBox::Yes | QMessageBox::No,
                  QMessageBox::No);
              allow_elevation = answer == QMessageBox::Yes;
              (void)use_chinese;
            }, Qt::BlockingQueuedConnection);
            if (allow_elevation) {
              run_windows_etw_observer_elevated(exe_dir, observe, warnings);
            }
          }
          if (!dynamic.present) {
            throw std::runtime_error("Windows ETW observation failed to start.");
          }
          options.dynamic_report_path = observe.output_path;
#else
          binsight::DockerObserveOptions observe;
          observe.binary_path = options.binary_path;
          observe.output_path = binsight::with_output_dir(options.output_dir, "dynamic.json");
          observe.image = docker_image;
          observe.network_mode = docker_network;
          observe.timeout_seconds = timeout;
          observe.risk_accepted = true;
          binsight::LinuxDockerObserver observer{binsight::ProcessRunner{}};
          const auto dynamic = observer.observe(observe, warnings);
          if (!dynamic.present) {
            throw std::runtime_error("Docker observation failed to start.");
          }
          options.dynamic_report_path = observe.output_path;
#endif
        }
        result = binsight::analyze_and_write_reports(options, exe_dir, warnings);
        std::ostringstream out;
        out << (use_chinese ? "扫描完成\n\n" : "Scan complete\n\n");
        out << (use_chinese ? "目标: " : "Target: ") << result.report.target.path << "\n";
        out << (use_chinese ? "格式: " : "Format: ") << result.report.target.format_name << "\n";
        out << (use_chinese ? "分析模式: " : "Analysis mode: ") << binsight::to_string(result.report.analysis_mode) << "\n";
        out << (use_chinese ? "最高风险: " : "Highest severity: ") << binsight::to_string(result.report.ai_analysis.severity) << "\n";
        out << (use_chinese ? "规则命中: " : "Rule findings: ") << result.report.rule_findings.size() << "\n";
        out << (use_chinese ? "可疑字符串: " : "Suspicious strings: ") << result.report.strings.size() << "\n";
        out << (use_chinese ? "RAG 条目: " : "RAG entries: ") << result.report.rag_context.size() << "\n";
        out << (use_chinese ? "警告: " : "Warnings: ") << result.report.warnings.size() << "\n\n";
        for (const auto& [path, language] : result.markdown_outputs) {
          out << "Markdown (" << binsight::to_string(language) << "): " << path << "\n";
        }
        out << "JSON: " << result.json_output << "\n";
        message = QString::fromStdString(out.str());
      } catch (const std::exception& ex) {
        ok = false;
        message = QString::fromStdString(std::string(use_chinese ? "扫描失败: " : "Scan failed: ") + ex.what());
      }

      QMetaObject::invokeMethod(qApp, [self, result, message, ok]() {
        if (!self) {
          return;
        }
        self->finish_scan(result, message, ok);
      }, Qt::QueuedConnection);
    }).detach();
  }

  void finish_scan(const binsight::ScanExecutionResult& result, const QString& message, bool ok) {
    set_running(false);
    result_text_->setPlainText(message);
    if (ok) {
      last_zh_report_.clear();
      last_en_report_.clear();
      for (const auto& [path, language] : result.markdown_outputs) {
        if (language == binsight::ReportLanguage::Chinese) {
          last_zh_report_ = path;
        } else if (language == binsight::ReportLanguage::English) {
          last_en_report_ = path;
        }
      }
      last_json_report_ = result.json_output;
    }
  }

  void set_running(bool running) {
    scan_button_->setEnabled(!running);
    test_connection_->setEnabled(!running);
    dynamic_button_->setEnabled(!running);
  }

  void open_file(const std::filesystem::path& path) {
    if (path.empty()) {
      QMessageBox::information(this, tr_text("open_title"), tr_text("no_file"));
      return;
    }
    QDesktopServices::openUrl(QUrl::fromLocalFile(qstring_from_path(path)));
  }

  DropLabel* drop_label_ = nullptr;
  QTabWidget* tabs_ = nullptr;
  QWidget* scan_page_ = nullptr;
  QWidget* config_page_ = nullptr;
  QLineEdit* file_path_ = nullptr;
  QPushButton* browse_file_ = nullptr;
  QLineEdit* output_dir_ = nullptr;
  QPushButton* browse_output_ = nullptr;
  QGroupBox* mode_group_ = nullptr;
  QComboBox* ui_language_ = nullptr;
  QLabel* ui_language_label_ = nullptr;
  QComboBox* report_language_ = nullptr;
  QLabel* report_language_label_ = nullptr;
  QCheckBox* dynamic_accept_ = nullptr;
  QLabel* docker_risk_label_ = nullptr;
  QSpinBox* dynamic_timeout_ = nullptr;
  QLabel* timeout_label_ = nullptr;
  QLineEdit* dynamic_image_ = nullptr;
  QLabel* docker_image_label_ = nullptr;
  QComboBox* dynamic_network_ = nullptr;
  QLabel* network_label_ = nullptr;
  QPushButton* scan_button_ = nullptr;
  QPushButton* dynamic_button_ = nullptr;
  QTextEdit* result_text_ = nullptr;
  QPushButton* open_zh_ = nullptr;
  QPushButton* open_en_ = nullptr;
  QPushButton* open_json_ = nullptr;
  QPushButton* open_dir_ = nullptr;
  QGroupBox* config_group_ = nullptr;
  QComboBox* provider_ = nullptr;
  QLabel* provider_label_ = nullptr;
  QLineEdit* base_url_ = nullptr;
  QLabel* base_url_label_ = nullptr;
  QComboBox* model_ = nullptr;
  QLabel* model_label_ = nullptr;
  QLineEdit* custom_model_ = nullptr;
  QLabel* custom_model_label_ = nullptr;
  QSpinBox* llm_timeout_ = nullptr;
  QLabel* llm_timeout_label_ = nullptr;
  QLineEdit* api_key_ = nullptr;
  QLabel* api_key_label_ = nullptr;
  QPushButton* save_config_ = nullptr;
  QPushButton* save_key_ = nullptr;
  QPushButton* test_connection_ = nullptr;
  QPushButton* show_config_ = nullptr;
  std::filesystem::path last_zh_report_;
  std::filesystem::path last_en_report_;
  std::filesystem::path last_json_report_;
};

}  // namespace

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      std::cout << "Usage: binsight-gui [binary]\n";
      return 0;
    }
  }

  QApplication app(argc, argv);
  MainWindow window;
  if (argc > 1) {
    window.set_initial_file(QString::fromLocal8Bit(argv[1]));
    window.show();
  } else {
    window.show();
  }
  return app.exec();
}
