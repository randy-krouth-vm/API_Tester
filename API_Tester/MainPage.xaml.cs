using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using ApiTester.Core;
using ApiTester.Shared;
using Microsoft.Extensions.DependencyInjection;
using API_Tester.SecurityCatalog;
#if WINDOWS
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Input;
using Windows.System;
using Windows.UI.Core;
#endif

namespace API_Tester
{
    public partial class MainPage : ContentPage
    {
        private readonly ScanWorkflowCoordinator _logic = new();
        private int _cvePage = 1;
        private const int CvePageSize = 250;
        private ResultPagingMode _pagingMode = ResultPagingMode.TextSummary;
        private static readonly Color ActiveNavColor = Color.FromArgb("#0F766E");
        private static readonly Color InactiveNavColor = Color.FromArgb("#6B7280");
        private int _resultsPage = 1;
        private int _resultRenderVersion;
        private const int ResultsPageLineCount = 250;
        
#if WINDOWS
        private FrameworkElement? _windowsRootElement;
        private bool _windowsGlobalKeyAttached;
#endif

        private HttpClient _httpClient
        {
            get => _logic.State.HttpClient;
            set => _logic.State.HttpClient = value;
        }

        private bool _startupInitialized
        {
            get => _logic.State.StartupInitialized;
            set => _logic.State.StartupInitialized = value;
        }

        private AsyncLocal<string?> _activeStandardTestKey => _logic.State.ActiveStandardTestKey;
        private AsyncLocal<AuthProfile?> _activeAuthProfile => _logic.State.ActiveAuthProfile;
        private AsyncLocal<bool> _strictSingleTargetMode => _logic.State.StrictSingleTargetMode;
        private AsyncLocal<Uri?> _strictSingleBaseUri => _logic.State.StrictSingleBaseUri;

        private string? _resultsFindQuery
        {
            get => _logic.State.ResultsFindQuery;
            set => _logic.State.ResultsFindQuery = value;
        }

        private int _resultsFindIndex
        {
            get => _logic.State.ResultsFindIndex;
            set => _logic.State.ResultsFindIndex = value;
        }

        private bool _resultsFindCaseSensitive
        {
            get => _logic.State.ResultsFindCaseSensitive;
            set => _logic.State.ResultsFindCaseSensitive = value;
        }

        private bool _suppressFindPromptOnNextInvoke
        {
            get => _logic.State.SuppressFindPromptOnNextInvoke;
            set => _logic.State.SuppressFindPromptOnNextInvoke = value;
        }

        private AsyncLocal<AuditCaptureContext?> _auditCaptureContext => _logic.State.AuditCaptureContext;
        private Dictionary<string, string> _baselineArtifactMap => _logic.State.BaselineArtifactMap;
        private Dictionary<string, OpenApiProbeContext> _openApiProbeContextCache => _logic.State.OpenApiProbeContextCache;

        private string _lastOpenApiInputRaw
        {
            get => _logic.State.LastOpenApiInputRaw;
            set => _logic.State.LastOpenApiInputRaw = value;
        }

        private string _rawResultsText
        {
            get => _logic.State.RawResultsText;
            set => _logic.State.RawResultsText = value;
        }

        private string _inMemoryRunLog
        {
            get => _logic.State.InMemoryRunLog;
            set => _logic.State.InMemoryRunLog = value;
        }

        private bool _captureRunProgressInMemory
        {
            get => _logic.State.CaptureRunProgressInMemory;
            set => _logic.State.CaptureRunProgressInMemory = value;
        }

        private string _renderedResultsText
        {
            get => _logic.State.RenderedResultsText;
            set => _logic.State.RenderedResultsText = value;
        }

        private bool _headlessAutoRunStarted
        {
            get => _logic.State.HeadlessAutoRunStarted;
            set => _logic.State.HeadlessAutoRunStarted = value;
        }

        private static int PrettyResultFormattingMaxChars => ScanWorkflowState.PrettyResultFormattingMaxChars;

        public MainPage()
        {
            InitializeComponent();
            CveCorpusService.ConfigureAppDataDirectoryProvider(() => FileSystem.AppDataDirectory);
            _logic.State.HttpClient = ResolveHttpClient();
            _logic.State.RawResultsText = "Use this only on APIs you own or are explicitly authorized to test.";
            RunScopePicker.SelectedIndex = 1;
            TypeAwareModePicker.SelectedIndex = 0;
            PayloadLocationPicker.SelectedIndex = 0;
            PriorityFilterPicker.SelectedIndex = 0;
            DefaultAuthProfilePicker.SelectedIndex = 0;
            ApplyResultView();
            Loaded += OnMainPageLoaded;
        }

        private static HttpClient ResolveHttpClient()
        {
            var services = Microsoft.Maui.Controls.Application.Current?.Handler?.MauiContext?.Services;
            var factory = services?.GetService<IHttpClientFactory>();
            if (factory is not null)
            {
                CveCorpusService.ConfigureHttpClientFactory(() => factory.CreateClient("NvdApi"));
                return factory.CreateClient("ApiTesterRuntime");
            }

            return new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        }

        private void OnMainPageLoaded(object? sender, EventArgs e)
        {
            if (_logic.State.StartupInitialized)
            {
                return;
            }

            _logic.State.StartupInitialized = true;
            Loaded -= OnMainPageLoaded;

            try
            {
                var startupText = ResultPresentation.BuildCveTestReference();
                ShowCveText(startupText);
                SetActiveNavButton("top");
                DefaultAuthProfilePicker.SelectedIndex = 0;
                _ = RefreshBaselineRunPickerAsync();
                TriggerHeadlessAutoRunIfEnabled();
#if WINDOWS
                AttachWindowsFindKeyHandling();
#endif
            }
            catch (Exception ex)
            {
                SetResult($"Startup initialization failed: {ex.Message}");
            }
        }

        private async void OnSyncCveCorpusClicked(object? sender, EventArgs e)
        {
            await _logic.OnSyncCveCorpusClickedAsync(
                SetBusy,
                SetProgressResult,
                () => _pagingMode = ResultPagingMode.TextSummary,
                ShowCveText,
                SetResult,
                async progress =>
                {
                    var meta = await CveCorpusService.SyncFromNvdAsync(progress);
                    var summary = await CveCorpusService.BuildSummaryAsync();
                    return (meta.Count, meta.TotalResults, summary);
                });
        }

        private async void OnLoadCveCorpusClicked(object? sender, EventArgs e)
        {
            await _logic.OnLoadCveCorpusClickedAsync(
                SetBusy,
                () => _pagingMode = ResultPagingMode.TextSummary,
                ShowCveText,
                AnnounceStatus,
                SetResult,
                () => Task.Run(() => CveCorpusService.BuildSummaryAsync()));
        }

        private async void OnRefreshBaselinesClicked(object? sender, EventArgs e)
        {
            await RefreshBaselineRunPickerAsync();
            AnnounceStatus("Baseline artifacts refreshed.");
        }   

        private async void OnBuildFunctionMapClicked(object? sender, EventArgs e)
        {
            await _logic.OnBuildFunctionMapClickedAsync(
                SetBusy,
                SetProgressResult,
                () => _pagingMode = ResultPagingMode.TextSummary,
                ShowCveText,
                AnnounceStatus,
                SetResult,
                async progress =>
                {
                    var meta = await CveCorpusService.BuildFunctionMapAsync(progress);
                    var summary = await Task.Run(() => CveCorpusService.BuildFunctionMapSummaryAsync());
                    return (meta.Count, meta.UniqueFunctionsCovered, summary);
                });
        }

        private async void OnLoadFunctionMapSummaryClicked(object? sender, EventArgs e)
        {
            await _logic.OnLoadFunctionMapSummaryClickedAsync(
                SetBusy,
                () => _pagingMode = ResultPagingMode.TextSummary,
                ShowCveText,
                AnnounceStatus,
                SetResult,
                () => Task.Run(() => CveCorpusService.BuildFunctionMapSummaryAsync()));
        }

        private async void OnFindCveClicked(object? sender, EventArgs e)
        {
            await _logic.OnFindCveClickedAsync(
                CveSearchEntry.Text,
                SetBusy,
                () => _pagingMode = ResultPagingMode.TextSummary,
                ShowCveText,
                AnnounceStatus,
                SetResult,
                query => Task.Run(() => CveCorpusService.BuildCveLookupAsync(query)));
        }

        private async void OnFindInResultsClicked(object? sender, EventArgs e)
        {
            await _logic.OnFindInResultsClickedAsync(
                _logic.State,
                PromptFindInResultsAsync,
                () => FindInResultsAsync(forward: true));
#if WINDOWS
            ResultsEditor.Focus();
#endif
        }

        private async Task<(bool Accepted, string Query, bool CaseSensitive)> PromptFindInResultsAsync()
        {
            var initial = string.IsNullOrWhiteSpace(_logic.State.ResultsFindQuery) ? string.Empty : _logic.State.ResultsFindQuery;
#if WINDOWS
            var textBox = new Microsoft.UI.Xaml.Controls.TextBox
            {
                Text = initial
            };

            var caseToggle = new Microsoft.UI.Xaml.Controls.CheckBox
            {
                Content = "Case sensitive",
                IsChecked = _logic.State.ResultsFindCaseSensitive,
                Margin = new Microsoft.UI.Xaml.Thickness(0, 10, 0, 0)
            };

            var panel = new Microsoft.UI.Xaml.Controls.StackPanel();
            panel.Children.Add(new Microsoft.UI.Xaml.Controls.TextBlock { Text = "Find:" });
            panel.Children.Add(textBox);
            panel.Children.Add(caseToggle);

            var dialog = new Microsoft.UI.Xaml.Controls.ContentDialog
            {
                Title = "Find in Results",
                PrimaryButtonText = "OK",
                CloseButtonText = "Cancel",
                DefaultButton = Microsoft.UI.Xaml.Controls.ContentDialogButton.Primary,
                Content = panel
            };

            if ((Window?.Handler?.PlatformView as Microsoft.UI.Xaml.Window)?.Content is FrameworkElement root)
            {
                dialog.XamlRoot = root.XamlRoot;
            }

            var result = await dialog.ShowAsync();
            return result == Microsoft.UI.Xaml.Controls.ContentDialogResult.Primary
            ? (true, textBox.Text ?? string.Empty, caseToggle.IsChecked == true)
            : (false, initial, _logic.State.ResultsFindCaseSensitive);
#else
            var query = await DisplayPromptAsync("Find in Results", "Find:", initialValue: initial, maxLength: 200, keyboard: Keyboard.Text);
            return query is null
            ? (false, initial, _logic.State.ResultsFindCaseSensitive)
            : (true, query, _logic.State.ResultsFindCaseSensitive);
#endif
        }

        private async Task FindInResultsAsync(bool forward)
        {
            await _logic.FindInResultsAsync(
                _logic.State,
                forward,
                () => ResultsEditor.Text ?? string.Empty,
                () => DisplayPromptAsync("Find in Results", "Find:", initialValue: string.Empty, maxLength: 200, keyboard: Keyboard.Text),
                (title, message, cancel) => DisplayAlertAsync(title, message, cancel),
                (matchIndex, length) =>
                {
                    ResultsEditor.CursorPosition = matchIndex;
                    ResultsEditor.SelectionLength = length;
                });
        }

#if WINDOWS
        private void AttachWindowsFindKeyHandling()
        {
            if (_windowsGlobalKeyAttached)
            {
                return;
            }

            var element = (Window?.Handler?.PlatformView as Microsoft.UI.Xaml.Window)?.Content as UIElement
            ?? Handler?.PlatformView as UIElement;
            if (element is null)
            {
                return;
            }

            _windowsRootElement = element as FrameworkElement;
            if (_windowsRootElement is null)
            {
                return;
            }

            _windowsRootElement.AddHandler(UIElement.KeyDownEvent, new KeyEventHandler(OnWindowsGlobalKeyDown), true);
            _windowsGlobalKeyAttached = true;
        }

        private async void OnWindowsGlobalKeyDown(object sender, KeyRoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_logic.State.ResultsFindQuery))
            {
                return;
            }

            var controlDown = (InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Control) & CoreVirtualKeyStates.Down) == CoreVirtualKeyStates.Down;
            var altDown = (InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Menu) & CoreVirtualKeyStates.Down) == CoreVirtualKeyStates.Down;
            if (controlDown || altDown)
            {
                return;
            }

            if (e.Key == VirtualKey.Enter)
            {
                e.Handled = true;
                _logic.State.SuppressFindPromptOnNextInvoke = true;
                await FindInResultsAsync(forward: true);
            }
        }
#endif

        private async void OnSaveLogClicked(object? sender, EventArgs e)
        {
            await _logic.OnSaveLogClickedAsync(
                _inMemoryRunLog ?? string.Empty,
                SetResult,
                SetBusy,
                () => Path.Combine(CveCorpusService.GetCacheDirectoryPath(), "logs"),
                () => DateTime.UtcNow,
                (path, text) => File.WriteAllTextAsync(path, text),
                AnnounceStatus);
        }

        private async void OnLoadLogClicked(object? sender, EventArgs e)
        {
            await _logic.OnLoadLogClickedAsync(
                async () =>
                {
                    var file = await FilePicker.Default.PickAsync(new PickOptions
                    {
                        PickerTitle = "Select log file"
                    });
                    return file?.FullPath;
                },
                path => File.ReadAllTextAsync(path),
                text =>
                {
                    _inMemoryRunLog = text;
                    _rawResultsText = text;
                },
                () => _pagingMode = ResultPagingMode.RunLogPaged,
                () => _resultsPage = 1,
                ApplyResultView,
                AnnounceStatus,
                SetResult);
        }

        private async void OnLoadCorpusPagedClicked(object? sender, EventArgs e)
        {
            await _logic.OnLoadCorpusPagedClickedAsync(
                () => _pagingMode = ResultPagingMode.CorpusPaged,
                () => _cvePage = 1,
                LoadCvePagedViewAsync);
        }

        private async void OnLoadFunctionMapPagedClicked(object? sender, EventArgs e)
        {
            await _logic.OnLoadFunctionMapPagedClickedAsync(
                () => _pagingMode = ResultPagingMode.FunctionMapPaged,
                () => _cvePage = 1,
                LoadFunctionMapTextPageAsync);
        }

        private async void OnPrevCvePageClicked(object? sender, EventArgs e)
        {
            await _logic.OnPrevPageClickedAsync(
                () => _pagingMode == ResultPagingMode.FunctionMapPaged,
                () => _pagingMode == ResultPagingMode.CorpusPaged,
                IsResultsPagingActive,
                () => _cvePage,
                value => _cvePage = value,
                LoadFunctionMapTextPageAsync,
                LoadCvePagedViewAsync,
                () => _resultsPage,
                value => _resultsPage = value,
                ApplyResultsPageView,
                AnnounceStatus);
        }

        private async void OnNextCvePageClicked(object? sender, EventArgs e)
        {
            await _logic.OnNextPageClickedAsync(
                () => _pagingMode == ResultPagingMode.FunctionMapPaged,
                () => _pagingMode == ResultPagingMode.CorpusPaged,
                IsResultsPagingActive,
                () => _cvePage,
                value => _cvePage = value,
                LoadFunctionMapTextPageAsync,
                LoadCvePagedViewAsync,
                () => _resultsPage,
                value => _resultsPage = value,
                ApplyResultsPageView,
                AnnounceStatus);
        }

        private async void OnGoToCvePageClicked(object? sender, EventArgs e)
        {
            await _logic.OnGoToPageClickedAsync(
                CvePageEntry.Text,
                SetResult,
                value => _cvePage = value,
                () => _pagingMode == ResultPagingMode.FunctionMapPaged,
                () => _pagingMode == ResultPagingMode.CorpusPaged,
                LoadFunctionMapTextPageAsync,
                LoadCvePagedViewAsync);
        }

        private async Task LoadCvePagedViewAsync()
        {
            SetBusy(true, $"Loading corpus page {_cvePage}...");
            try
            {
                _pagingMode = ResultPagingMode.CorpusPaged;
                var pageText = await CveCorpusService.BuildCorpusPageAsync(_cvePage, CvePageSize);
                var page = await CveCorpusService.GetCorpusPageAsync(_cvePage, CvePageSize);
                _cvePage = page.Page;
                ShowCveText(pageText);
                AnnounceStatus($"Loaded corpus page {_cvePage}.");
            }
            catch (Exception ex)
            {
                SetResult($"Paged load failed: {ex.Message}");
            }
            finally
            {
                SetBusy(false);
            }
        }

        private async Task LoadFunctionMapTextPageAsync()
        {
            var selectedPriority = PriorityFilterPicker.SelectedItem?.ToString() ?? "Off";
            var loadingMessage = selectedPriority.Equals("Off", StringComparison.OrdinalIgnoreCase)
            ? "Loading Function Map Paged View..."
            : "Loading Rows...";
            SetBusy(true, loadingMessage);
            try
            {
                _pagingMode = ResultPagingMode.FunctionMapPaged;
                if (!await CveCorpusService.HasFunctionMapAsync())
                {
                    ShowCveText("Function-map files are not present yet.\n\nRun:\n1) Build CVE Function Map\n2) Load Function Map Paged View");
                    SetResult("Function-map files not found. Build the map first.");
                    return;
                }

                CveFunctionMapPageResult? page = null;
                CveFunctionMapPageRow[] filteredRows;
                if (selectedPriority.Equals("Off", StringComparison.OrdinalIgnoreCase))
                {
                    page = await CveCorpusService.GetFunctionMapPageAsync(_cvePage, CvePageSize);
                    _cvePage = page.Page;
                    filteredRows = page.Rows.ToArray();
                }
                else
                {
                    page = await CveCorpusService.GetFunctionMapFilteredPageAsync(selectedPriority, _cvePage, CvePageSize);
                    _cvePage = page.Page;
                    filteredRows = page.Rows.ToArray();
                }

                var report = await Task.Run(() => BuildFunctionMapReport(page, selectedPriority, filteredRows));
                ShowCveText(report);
                var status = selectedPriority.Equals("Off", StringComparison.OrdinalIgnoreCase)
                ? $"Loaded function-map text page {_cvePage}."
                : $"Loaded {selectedPriority.ToUpperInvariant()} filtered page {_cvePage}.";
                AnnounceStatus(status);
            }
            catch (Exception ex)
            {
                SetResult($"Failed to load function-map page: {ex.Message}");
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void ShowCveText(string text)
        {
            _rawResultsText = text ?? string.Empty;
            ApplyResultView();
        }

        private void ShowCveGrid(string pageInfo)
        {
            ShowCveText(pageInfo);
        }

        private async void OnApplyPriorityFilterClicked(object? sender, EventArgs e)
        {
            await _logic.OnApplyPriorityFilterClickedAsync(
                () => _pagingMode == ResultPagingMode.FunctionMapPaged,
                () => _cvePage = 1,
                LoadFunctionMapTextPageAsync,
                AnnounceStatus);
        }

        private async void OnPriorityFilterChanged(object? sender, EventArgs e)
        {
            _logic.OnPriorityFilterChanged(
                () => _pagingMode == ResultPagingMode.FunctionMapPaged,
                AnnounceStatus);
        }

        private async void OnNavigateSectionClicked(object? sender, EventArgs e)
        {
            if (sender is not Button { CommandParameter: string targetKey } || string.IsNullOrWhiteSpace(targetKey))
            {
                return;
            }

            VisualElement? anchor = targetKey.Trim().ToLowerInvariant() switch
            {
                "top" => TopSectionAnchor,
                "target" => TargetSectionAnchor,
                "tests" => IndividualTestsSectionAnchor,
                "app-standards" => AppStandardsSectionAnchor,
                "us-federal" => UsFederalSectionAnchor,
                "international" => InternationalSectionAnchor,
                "run" => RunSectionAnchor,
                "cloud-infra" => CloudInfraSectionAnchor,
                "cve" => CveSectionAnchor,
                "results" => ResultsSectionAnchor,
                "bottom" => BottomSectionAnchor,
                _ => null
            };

            if (anchor is null)
            {
                return;
            }

            try
            {
                await MainScrollView.ScrollToAsync(anchor, ScrollToPosition.Start, true);
                SetActiveNavButton(targetKey);
            }
            catch
            {
                // Ignore non-critical scroll navigation errors.
            }
        }

        private void SetActiveNavButton(string targetKey)
        {
            var key = targetKey.Trim().ToLowerInvariant();
            var map = new Dictionary<string, Button>(StringComparer.Ordinal)
            {
                ["top"] = NavTopButton,
                ["target"] = NavTargetButton,
                ["tests"] = NavTestsButton,
                ["app-standards"] = NavAppStandardsButton,
                ["us-federal"] = NavUsFederalButton,
                ["international"] = NavInternationalButton,
                ["run"] = NavRunAllButton,
                ["cloud-infra"] = NavCloudInfraButton,
                ["cve"] = NavCveButton,
                ["results"] = NavResultsButton,
                ["bottom"] = NavBottomButton
            };

            foreach (var button in map.Values)
            {
                button.BackgroundColor = InactiveNavColor;
                button.TextColor = Colors.White;
            }

            if (map.TryGetValue(key, out var active))
            {
                active.BackgroundColor = ActiveNavColor;
                active.TextColor = Colors.White;
            }
        }

        private static string BuildFunctionMapReport(
        CveFunctionMapPageResult? page,
        string selectedPriority,
        IReadOnlyList<CveFunctionMapPageRow> filteredRows) =>
            ResultPresentation.BuildFunctionMapReport(page, selectedPriority, filteredRows);

        private async void OnTestSsrfClicked(object? sender, EventArgs e) =>
        await ExecuteSingleTestAsync("SSRF", RunMITREATTampCKFrameworkSsrfTestsAsync);

        private async void OnTestXssClicked(object? sender, EventArgs e) =>
        await ExecuteSingleTestAsync("XSS", RunXssTestsAsync);

        private async void OnTestSqliClicked(object? sender, EventArgs e) =>
        await ExecuteSingleTestAsync("SQL Injection", RunSqlInjectionTestsAsync);

        private async void OnTestHeadersClicked(object? sender, EventArgs e) =>
        await ExecuteSingleTestAsync("Security Headers", RunSecurityHeaderTestsAsync);

        private async void OnTestCorsClicked(object? sender, EventArgs e) =>
        await ExecuteSingleTestAsync("CORS", RunCorsTestsAsync);

        private async void OnTestMethodsClicked(object? sender, EventArgs e) =>
        await ExecuteSingleTestAsync("HTTP Methods", RunHttpMethodTestsAsync);

        private async void OnShowCatalogClicked(object? sender, EventArgs e)
        {
            await _logic.OnShowCatalogClickedAsync(
                SetBusy,
                async () => await SecurityCatalogLoader.LoadAsync(FileSystem.OpenAppPackageFileAsync),
                catalog => SecurityCatalogLoader.BuildCatalogReport((SecurityTestCatalog)catalog),
                () => SecurityCatalogLoader.LastLoadError,
                SetResult);
        }

        private async void OnSpiderSiteClicked(object? sender, EventArgs e)
        {
            Uri? currentTarget = null;
            await _logic.OnSpiderSiteClickedAsync(
                () => TryGetTargetUri(out currentTarget),
                () => currentTarget!,
                SetBusy,
                RunSiteSpiderAndCoverageAsync,
                SetResult);
        }

        private async void OnRunMaxCoverageClicked(object? sender, EventArgs e)
        {
            Uri? currentTarget = null;
            await _logic.OnRunMaxCoverageClickedAsync(
                () => TryGetTargetUri(out currentTarget),
                () => currentTarget!,
                SetBusy,
                SetProgressResult,
                RunMaximumCoverageAssessmentAsync,
                SetResult);
        }

        private async void OnRunFrameworkClicked(object? sender, EventArgs e)
        {
            await _logic.OnRunFrameworkClickedAsync(
                (sender as Button)?.CommandParameter as string,
                GetFrameworkPackFor,
                SetResult,
                ExecuteFrameworkPackAsync);
        }

        private async void OnRunFrameworkTestClicked(object? sender, EventArgs e)
        {
            await _logic.OnRunFrameworkTestClickedAsync(
                (sender as Button)?.CommandParameter as string,
                ResolveTestByKey,
                GetFrameworkCategory,
                GetComplianceMappings,
                GetSpecificationForTestKey,
                WrapWithStandardContext,
                SetResult,
                ExecuteFrameworkPackAsync);
        }

        private Func<Uri, Task<string>> WrapWithStandardContext(string testKey, Func<Uri, Task<string>> test)
        {
            return async uri =>
            {
                var previous = _activeStandardTestKey.Value;
                _activeStandardTestKey.Value = testKey;
                try
                {
                    return await test(uri);
                }
                finally
                {
                    _activeStandardTestKey.Value = previous;
                }
            };
        }

        private static string GetFrameworkCategory(string frameworkName)
        {
            return Mappings.GetFrameworkCategory(frameworkName);
        }

        private (string Category, Func<Uri, Task<string>>[] Tests)? GetFrameworkPackFor(string frameworkName)
            => FrameworkResolutionWorkflowUtilities.GetFrameworkPackFor(this, frameworkName);

        private (string TestName, Func<Uri, Task<string>>? Test) ResolveTestByKey(string testKey)
            => FrameworkResolutionWorkflowUtilities.ResolveTestByKey(this, testKey);

        private static string GetSpecificationForTestKey(string testKey)
        {
            return Mappings.GetSpecificationForTestKey(testKey);
        }

        private static List<string> GetComplianceMappings(string frameworkName, string testKey)
        {
            return Mappings.GetComplianceMappings(frameworkName, testKey);
        }

        private async void OnRunApiAppStandardsClicked(object? sender, EventArgs e)
        {
            await RunStandardFrameworkCategoryAsync("1) Application & API-Specific Standards");
        }

        private async void OnRunUsFederalStandardsClicked(object? sender, EventArgs e)
        {
            await RunStandardFrameworkCategoryAsync("2) U.S. Federal / Government Standards");
        }

        private async void OnRunInternationalStandardsClicked(object? sender, EventArgs e)
        {
            await RunStandardFrameworkCategoryAsync("3) International Security Standards");
        }

        private async void OnRunCloudInfraStandardsClicked(object? sender, EventArgs e)
        {
            await RunStandardFrameworkCategoryAsync("4) Cloud & Infrastructure Security Standards");
        }

        private async void OnRunIndustryRegulatoryStandardsClicked(object? sender, EventArgs e)
        {
            await RunStandardFrameworkCategoryAsync("5) Industry & Regulatory Frameworks");
        }

        private async void OnRunTestingAssuranceStandardsClicked(object? sender, EventArgs e)
        {
            await RunStandardFrameworkCategoryAsync("6) Testing & Assurance Standards");
        }

        private async void OnRunArchitectureZeroTrustStandardsClicked(object? sender, EventArgs e)
        {
            await RunStandardFrameworkCategoryAsync("7) Architecture & Zero Trust");
        }

        private async void OnRunSdlcDevSecOpsStandardsClicked(object? sender, EventArgs e)
        {
            await RunStandardFrameworkCategoryAsync("8) Secure SDLC & DevSecOps Standards");
        }

        private async Task RunStandardFrameworkCategoryAsync(string categoryName)
        {
            var pack = SuiteCatalogMappings.GetStandardFrameworkPack(categoryName);
            if (pack is null)
            {
                SetResult($"Unknown standards category: {categoryName}");
                return;
            }

            var tests = DelegateResolutionUtilities.ResolveTestDelegates(this, pack.TestMethodNames);
            if (tests.Length == 0)
            {
                SetResult($"No tests are currently available for standards category: {categoryName}");
                return;
            }

            await ExecuteFrameworkPackAsync(
                pack.CategoryName,
                pack.Frameworks,
                tests,
                SuiteCatalogMappings.GetStandardFrameworkRunMessage(pack.CategoryName));
        }

        private async void OnRunAllFrameworksClicked(object? sender, EventArgs e)
        {
            Uri? currentTarget = null;
            await _logic.OnRunCompositeReportClickedAsync(
                () => TryGetTargetUri(out currentTarget),
                () => currentTarget!,
                ResetInMemoryRunLog,
                capture => _captureRunProgressInMemory = capture,
                () => _pagingMode = ResultPagingMode.TextSummary,
                SetBusy,
                "Running all standards categories...",
                "Run All Standards Categories",
                "Run-all execution failed",
                async target =>
                {
                    var report = await RunOrchestrationWorkflowUtilities.BuildRunAllFrameworksReportAsync(
                        target,
                        GetStandardFrameworkPacks(),
                        BuildControlDrivenFrameworkPackReportAsync,
                        IsSpiderRouteScopeSelected(),
                        crawlTarget => CrawlSiteAsync(crawlTarget),
                        BuildRouteDiscoverySummary,
                        RunSpiderRouteHitPassAsync,
                        (sweepTarget, endpoints) => RunAdaptiveEndpointSweepAsync(sweepTarget, endpoints));
                    return await AppendManualPayloadDirectRequestsIfEnabledAsync(target, report);
                },
                AppendRunLogSection);
        }

        private async void OnRunEverythingClicked(object? sender, EventArgs e)
        {
            Uri? currentTarget = null;
            await _logic.OnRunCompositeReportClickedAsync(
                () => TryGetTargetUri(out currentTarget),
                () => currentTarget!,
                ResetInMemoryRunLog,
                capture => _captureRunProgressInMemory = capture,
                () => _pagingMode = ResultPagingMode.TextSummary,
                SetBusy,
                "Running full coverage (standards + suites + advanced)...",
                "Run Everything",
                "Run-everything failed",
                async target =>
                {
                    var report = await RunOrchestrationWorkflowUtilities.BuildRunEverythingReportAsync(
                        target,
                        GetStandardFrameworkPacks(),
                        SuiteCatalogMappings.GetDefaultNamedSuiteExecutionOrder(),
                        TryGetNamedSuiteRun,
                        BuildControlDrivenFrameworkPackReportAsync,
                        BuildRemainingAdvancedProbeReportAsync,
                        IsSpiderRouteScopeSelected(),
                        crawlTarget => CrawlSiteAsync(crawlTarget),
                        BuildRouteDiscoverySummary,
                        RunSpiderRouteHitPassAsync,
                        (sweepTarget, endpoints) => RunAdaptiveEndpointSweepAsync(sweepTarget, endpoints));
                    return await AppendManualPayloadDirectRequestsIfEnabledAsync(target, report);
                },
                AppendRunLogSection);
        }

        private async void OnRunValidationHarnessClicked(object? sender, EventArgs e)
        {
            await _logic.OnRunValidationHarnessClickedAsync(
                ResetInMemoryRunLog,
                SetBusy,
                RunValidationHarnessAsync,
                SetResult);
        }

        private async Task<string> RunValidationHarnessAsync()
        {
            return await ValidationWorkflowUtilities.RunValidationHarnessAsync(
                Environment.GetEnvironmentVariable("API_TESTER_VALIDATION_SCENARIOS"),
                FileSystem.Current.AppDataDirectory,
                GetExecutionAuthProfiles,
                RunReportUtilities.IsUnauthProfileName,
                NormalizeAuthProfileSelection,
                RunReportUtilities.GetAuthProfileDisplayName,
                ResolveTestByKey,
                ExecuteValidationResolvedTestAsync);
        }

        private async Task<(string Output, bool HadException)> ExecuteValidationResolvedTestAsync(
            string key,
            AuthProfile profile,
            Uri target,
            Func<Uri, Task<string>> test)
        {
            _activeStandardTestKey.Value = key;
            _activeAuthProfile.Value = profile;
            var hadException = false;
            string output;
            try
            {
                output = await test(target);
            }
            catch (Exception ex)
            {
                hadException = true;
                output = $"[{key}]{Environment.NewLine}Target: {target}{Environment.NewLine}- Execution error: {ex.Message}";
            }
            finally
            {
                _activeStandardTestKey.Value = null;
                _activeAuthProfile.Value = null;
            }

            return (output, hadException);
        }

        private static string BuildRouteDiscoverySummary(SpiderResult crawl) =>
            RunReportUtilities.BuildRouteDiscoverySummary(crawl);

        private Task<string> RunSpiderRouteHitPassAsync(Uri baseUri, IEnumerable<string> discoveredEndpoints) =>
            ScopeWorkflowUtilities.RunSpiderRouteHitPassAsync(baseUri, discoveredEndpoints, SafeSendAsync, FormatStatus, TryGetRoutePathKey);

        private static bool IsCiExtrasEnabled() => RunReportUtilities.IsCiExtrasEnabled();

        private static string TryGetRoutePathKey(string endpoint) => RunReportUtilities.TryGetRoutePathKey(endpoint);

        private static string TryGetRoutePathKey(Uri uri) => RunReportUtilities.TryGetRoutePathKey(uri);

        private RunScopeMode GetRunScopeMode()
        {
            return ScanOptionUtilities.GetRunScopeMode(
                Environment.GetEnvironmentVariable("API_TESTER_RUN_SCOPE"),
                RunScopePicker.SelectedIndex,
                RunScopePicker.SelectedItem?.ToString());
        }

        private bool IsSpiderRouteScopeSelected()
        {
            return GetRunScopeMode() == RunScopeMode.SpiderRoutes;
        }

        private bool IsOpenApiRouteScopeSelected()
        {
            return GetRunScopeMode() == RunScopeMode.OpenApiRoutes;
        }

        private bool IsTypeAwareModeEnabled()
        {
            return ScanOptionUtilities.IsTypeAwareModeEnabled(
                Environment.GetEnvironmentVariable("API_TESTER_TYPE_HANDLING"),
                Environment.GetEnvironmentVariable("API_TESTER_TYPE_AWARE"),
                TypeAwareModePicker.SelectedItem?.ToString());
        }

        private string GetSelectedScopeLabel() => ScanOptionUtilities.GetScopeLabel(GetRunScopeMode());

        private IEnumerable<(string CategoryName, string[] Frameworks, Func<Uri, Task<string>>[] Tests)> GetStandardFrameworkPacks()
            => FrameworkResolutionWorkflowUtilities.GetStandardFrameworkPacks(this);

        private Task<string> BuildRemainingAdvancedProbeReportAsync(Uri uri, HashSet<string> alreadyExecutedMethodNames)
            => DescriptorUtilities.BuildRemainingAdvancedProbeReportAsync(uri, alreadyExecutedMethodNames, GetAllDynamicProbes());

        private async void OnRunNamedSuiteClicked(object? sender, EventArgs e)
        {
            if (sender is not Button { CommandParameter: string suiteKey })
            {
                SetResult("Suite button is not configured correctly.");
                return;
            }

            var suite = GetNamedSuite(suiteKey);
            if (suite is null)
            {
                SetResult($"Unknown suite key: {suiteKey}");
                return;
            }

            await ExecuteFrameworkPackAsync(
            "10) Domain Security Suites",
            new[] { suite.Value.Name, $"Method count: {suite.Value.Tests.Length}" },
            suite.Value.Tests,
            $"Running {suite.Value.Name}...");
        }

        private (string Name, Func<Uri, Task<string>>[] Tests)? GetNamedSuite(string suiteKey)
            => FrameworkResolutionWorkflowUtilities.GetNamedSuite(this, suiteKey);

        private ResolvedNamedSuiteRun? TryGetNamedSuiteRun(string suiteKey)
            => FrameworkResolutionWorkflowUtilities.TryGetNamedSuiteRun(this, suiteKey);

        private async Task ExecuteSingleTestAsync(string name, Func<Uri, Task<string>> test)
        {
            Uri? currentTarget = null;
            await _logic.ExecuteSingleTestAsync(
                name,
                () => TryGetTargetUri(out currentTarget),
                () => currentTarget!,
                ResetInMemoryRunLog,
                SetBusy,
                GetSelectedScopeLabel,
                (enabled, uri) =>
                {
                    _strictSingleTargetMode.Value = enabled;
                    _strictSingleBaseUri.Value = uri;
                },
                async uri =>
                {
                    var report = await test(uri);
                    return await AppendManualPayloadDirectRequestsIfEnabledAsync(uri, report);
                },
                ResolveScopeTargetsAsync,
                AppendRunLogSection);
        }

        private async Task ExecuteFrameworkPackAsync(
        string categoryName,
        IEnumerable<string> frameworks,
        IEnumerable<Func<Uri, Task<string>>> tests,
        string runMessage)
        {
            Uri? currentTarget = null;
            var frameworkList = frameworks.ToList();
            var fallbackTests = tests.ToList();
            await _logic.ExecuteFrameworkPackAsync(
                categoryName,
                runMessage,
                () => TryGetTargetUri(out currentTarget),
                () => currentTarget!,
                ResetInMemoryRunLog,
                SetBusy,
                async () =>
                {
                    var report = await BuildControlDrivenFrameworkPackReportAsync(categoryName, frameworkList, currentTarget!, fallbackTests);
                    return await AppendManualPayloadDirectRequestsIfEnabledAsync(currentTarget!, report);
                },
                SetResult);
        }

        private async Task<string> AppendManualPayloadDirectRequestsIfEnabledAsync(Uri baseUri, string report)
        {
            if (!IsManualPayloadModeEnabled())
            {
                return report;
            }

            var directRequests = await RunManualPayloadDirectRequestsAsync(baseUri);
            return string.IsNullOrWhiteSpace(report)
                ? directRequests
                : $"{report}{Environment.NewLine}{Environment.NewLine}{directRequests}";
        }

        private async Task<string> BuildControlDrivenFrameworkPackReportAsync(
        string categoryName,
        IReadOnlyList<string> frameworkList,
        Uri uri,
        IReadOnlyList<Func<Uri, Task<string>>> fallbackTests)
        {
            var strictSingleMode = GetSelectedScopeLabel() == "Single Target";
            _strictSingleTargetMode.Value = strictSingleMode;
            _strictSingleBaseUri.Value = strictSingleMode ? uri : null;
            try
            {
                return await FrameworkPackExecutionWorkflowUtilities.BuildControlDrivenFrameworkPackReportAsync(
                    categoryName,
                    frameworkList,
                    uri,
                    fallbackTests,
                    ResolveScopeTargetsAsync,
                    BuildFrameworkTestDescriptors,
                    GetExecutionAuthProfiles,
                    RunReportUtilities.GetAuthProfileDisplayName,
                    SetBusy,
                    capture => _auditCaptureContext.Value = capture,
                    profile => _activeAuthProfile.Value = profile,
                    ExecuteBusinessLogicScenariosAsync,
                    GetSelectedBaselinePath,
                    BuildDeltaSummaryAsync,
                    BuildRoleDifferentialSummary,
                    GetSelectedScopeLabel,
                    SaveAuditArtifactAsync);
            }
            finally
            {
                _strictSingleTargetMode.Value = false;
                _strictSingleBaseUri.Value = null;
            }
        }

        private List<FrameworkTestDescriptor> BuildFrameworkTestDescriptors(
        string categoryName,
        IReadOnlyList<string> frameworks,
        IReadOnlyList<Func<Uri, Task<string>>> fallbackTests)
            => DescriptorUtilities.BuildFrameworkTestDescriptors(
                categoryName,
                frameworks,
                fallbackTests,
                Mappings.GetFrameworkControlKeys,
                ResolveTestByKey,
                WrapWithStandardContext);

        private List<AuthProfile> GetExecutionAuthProfiles()
        {
            return AuthProfileUtilities.GetExecutionProfiles(
                UserBearerEntry.Text,
                UserApiKeyEntry.Text,
                UserCookieEntry.Text,
                UserExtraHeadersEntry.Text,
                AdminBearerEntry.Text,
                AdminApiKeyEntry.Text,
                AdminCookieEntry.Text,
                AdminExtraHeadersEntry.Text,
                RoleMatrixSwitch.IsToggled || RunReportUtilities.IsTruthyEnvironment("API_TESTER_ROLE_MATRIX"),
                DefaultAuthProfilePicker.SelectedItem?.ToString(),
                Environment.GetEnvironmentVariable("API_TESTER_AUTH_DEFAULT"));
        }

        private static string? NormalizeAuthProfileSelection(string? value) =>
            AuthProfileUtilities.NormalizeAuthProfileSelection(value);

        private int GetEffectiveRequestDelayMs()
        {
            return ScanOptionUtilities.GetEffectiveRequestDelayMs(
                RequestDelayMsEntry.Text,
                Environment.GetEnvironmentVariable("API_TESTER_REQUEST_DELAY_MS"),
                RunReportUtilities.IsTruthyEnvironment("API_TESTER_HEADLESS"),
                Environment.GetEnvironmentVariable("API_TESTER_HEADLESS_REQUEST_DELAY_MS"));
        }

        private static string BuildRoleDifferentialSummary(IReadOnlyList<TestEvidenceRecord> records) =>
            RunReportUtilities.BuildRoleDifferentialSummary(records);

        private async Task<(string Source, string PreviousHash)> ExecuteBusinessLogicScenariosAsync(
        Uri baseUri,
        IReadOnlyList<AuthProfile> runProfiles,
        string categoryName,
        List<string> sections,
        List<TestEvidenceRecord> records,
        string previousHash)
        {
            return await BusinessScenarioWorkflowUtilities.ExecuteBusinessLogicScenariosAsync(
                Environment.GetEnvironmentVariable("API_TESTER_BUSINESS_SCENARIOS"),
                baseUri,
                runProfiles,
                categoryName,
                sections,
                records,
                previousHash,
                (scenario, profile, targetBaseUri) => BusinessScenarioWorkflowUtilities.ExecuteBusinessScenarioAsync(
                    scenario,
                    profile,
                    targetBaseUri,
                    SafeSendAsync,
                    capture => _auditCaptureContext.Value = capture,
                    activeProfile => _activeAuthProfile.Value = activeProfile,
                    RunReportUtilities.GetAuthProfileDisplayName));
        }

        private Task<IReadOnlyList<Uri>> ResolveScopeTargetsAsync(Uri baseUri) =>
            ScopeWorkflowUtilities.ResolveScopeTargetsAsync(
                baseUri,
                IsOpenApiRouteScopeSelected(),
                IsSpiderRouteScopeSelected(),
                GetOpenApiProbeContextAsync,
                uri => CrawlSiteAsync(uri));

        private async void OnPickOpenApiFileClicked(object? sender, EventArgs e)
        {
            try
            {
                var file = await FilePicker.Default.PickAsync(new PickOptions
                {
                    PickerTitle = "Select OpenAPI JSON file"
                });

                if (file is null)
                {
                    return;
                }

                OpenApiInputEntry.Text = file.FullPath;
                _openApiProbeContextCache.Clear();
                SetResult($"OpenAPI file selected: {file.FullPath}");
            }
            catch (Exception ex)
            {
                SetResult($"OpenAPI file selection failed: {ex.Message}");
            }
        }

        private bool TryGetTargetUri(out Uri uri)
        {
            var resolution = TargetResolutionWorkflowUtilities.ResolveTargetUri(
                UrlEntry.Text,
                Environment.GetEnvironmentVariable("API_TESTER_TARGET_URL"),
                Environment.GetEnvironmentVariable("API_TESTER_URL"),
                () =>
                {
                    var inferred = TryInferTargetUriFromOpenApiInput(out var value);
                    return (inferred, inferred ? value : null);
                },
                IsScopeAuthorizationEnforced(),
                AuditResultUtilities.GetScopeAuthorizationState);

            if (!resolution.Success || resolution.TargetUri is null)
            {
                SetResult(resolution.ErrorMessage ?? "Failed to resolve target URL.");
                uri = null!;
                return false;
            }

            if (resolution.InferredTargetUri is not null)
            {
                UrlEntry.Text = resolution.InferredTargetUri.ToString();
            }

            uri = resolution.TargetUri;
            return true;
        }

        private bool TryInferTargetUriFromOpenApiInput(out Uri uri)
        {
            return ScanOptionUtilities.TryInferTargetUriFromOpenApiInput(GetOpenApiInputRaw(), out uri);
        }

        private static Uri InferBaseTargetFromOpenApiUri(Uri openApiUri) =>
            ScanOptionUtilities.InferBaseTargetFromOpenApiUri(openApiUri);

        private static bool IsScopeAuthorizationEnforced() =>
            ScanOptionUtilities.IsScopeAuthorizationEnforced(Environment.GetEnvironmentVariable("API_TESTER_ENFORCE_SCOPE_AUTH"));

        private string GetScanDepthProfile()
        {
            return LegacyTestHarnessUtilities.GetScanDepthProfile();
        }

        private T[] LimitByScanDepth<T>(T[] items, int fastCount, int balancedCount)
        {
            return LegacyTestHarnessUtilities.LimitByScanDepth(items, GetScanDepthProfile(), fastCount, balancedCount);
        }

        private bool IsManualPayloadModeEnabled()
        {
            return ScanOptionUtilities.IsManualPayloadModeEnabled(
                ManualPayloadModeSwitch.IsToggled,
                RunReportUtilities.IsTruthyEnvironment("API_TESTER_MANUAL_PAYLOAD_MODE"));
        }

        private void AddVerbosePayloadDetails(List<string> findings, IEnumerable<string> payloads, IEnumerable<string> queryFields, IEnumerable<string>? bodyFields = null)
        {
            // Verbose payload detail output intentionally disabled.
        }

        private string[] GetManualPayloadsOrDefault(IEnumerable<string> defaults)
            => GetManualPayloadsOrDefault(defaults, ManualPayloadCategory.Generic);

        private string[] GetManualPayloadsOrDefault(IEnumerable<string> defaults, ManualPayloadCategory category)
        {
            var manual = ManualPayloadUtilities.ParseManualPayloads(
                IsManualPayloadModeEnabled(),
                ManualPayloadsEditor.Text,
                Environment.GetEnvironmentVariable("API_TESTER_MANUAL_PAYLOADS"));
            var filtered = ManualPayloadUtilities.FilterManualPayloads(manual, category);
            return ManualPayloadUtilities.MergePayloads(defaults, filtered, GetSchemeVariantPreference());
        }

        private string[] GetManualPayloadDirectRequestUrls()
        {
            var manual = ManualPayloadUtilities.ParseManualPayloads(
                IsManualPayloadModeEnabled(),
                ManualPayloadsEditor.Text,
                Environment.GetEnvironmentVariable("API_TESTER_MANUAL_PAYLOADS"));
            return ManualPayloadUtilities.ExtractDirectRequestUrls(manual, GetSchemeVariantPreference());
        }

        private string GetSchemeVariantPreference()
        {
            if (TryGetConfiguredTargetUriForOverrides(out var configured))
            {
                return configured.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                    ? "HTTPS"
                    : configured.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                        ? "HTTP"
                        : "Both";
            }

            var openApiInput = GetOpenApiInputRaw();
            if (Uri.TryCreate(openApiInput, UriKind.Absolute, out var openApiUri))
            {
                return openApiUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                    ? "HTTPS"
                    : openApiUri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                        ? "HTTP"
                        : "Both";
            }

            var envValue = Environment.GetEnvironmentVariable("API_TESTER_SCHEME_VARIANTS");
            if (!string.IsNullOrWhiteSpace(envValue))
            {
                return envValue;
            }

            return "Both";
        }

        private static string GetAuditArtifactRoot()
        {
            return AuditArtifactStorage.GetAuditArtifactRoot(FileSystem.Current.AppDataDirectory);
        }

        private async Task RefreshBaselineRunPickerAsync()
        {
            try
            {
                await Task.Run(() =>
                {
                    var root = GetAuditArtifactRoot();
                    var items = AuditArtifactStorage.EnumerateBaselineArtifacts(root);
                    MainThread.BeginInvokeOnMainThread(() =>
                    {
                        BaselineRunPicker.Items.Clear();
                        _baselineArtifactMap.Clear();
                        BaselineRunPicker.Items.Add("Auto (latest previous run)");
                        _baselineArtifactMap["Auto (latest previous run)"] = string.Empty;
                        foreach (var item in items)
                        {
                            BaselineRunPicker.Items.Add(item.Label);
                            _baselineArtifactMap[item.Label] = item.Path;
                        }

                        if (BaselineRunPicker.SelectedIndex < 0)
                        {
                            BaselineRunPicker.SelectedIndex = 0;
                        }
                    });
                });
            }
            catch
            {
                // Non-fatal UI helper.
            }
        }

        private string? GetSelectedBaselinePath()
        {
            var selected = BaselineRunPicker.SelectedItem?.ToString();
            if (string.IsNullOrWhiteSpace(selected))
            {
                return null;
            }

            if (_baselineArtifactMap.TryGetValue(selected, out var path) && !string.IsNullOrWhiteSpace(path))
            {
                return path;
            }

            return null;
        }

        private async Task<string> BuildDeltaSummaryAsync(string categoryName, IReadOnlyList<TestEvidenceRecord> current, string? baselinePath = null)
        {
            return await AuditArtifactStorage.BuildDeltaSummaryAsync(current, GetAuditArtifactRoot(), baselinePath);
        }

        private async Task<string> SaveAuditArtifactAsync(AuditRunArtifact artifact)
        {
            var jsonPath = await AuditArtifactStorage.SaveAuditArtifactAsync(
                artifact,
                GetAuditArtifactRoot(),
                BuildPciReportMarkdown,
                BuildTraceabilityCsv);
            _ = RefreshBaselineRunPickerAsync();
            return jsonPath;
        }

        private static string BuildPciReportMarkdown(AuditRunArtifact artifact) =>
            AuditArtifactPresentation.BuildPciReportMarkdown(artifact);

        private static string BuildTraceabilityCsv(AuditRunArtifact artifact) =>
            AuditArtifactPresentation.BuildTraceabilityCsv(artifact);

        private async Task<string> RunSiteSpiderAndCoverageAsync(Uri baseUri)
        {
            var report = await CoverageWorkflowUtilities.RunSiteSpiderAndCoverageAsync(
                baseUri,
                uri => CrawlSiteAsync(uri),
                BuildSpiderCoverageHints);
            return await AppendManualPayloadDirectRequestsIfEnabledAsync(baseUri, report);
        }

        private async Task<string> RunMaximumCoverageAssessmentAsync(Uri baseUri, IProgress<string>? progress = null)
        {
            var report = await CoverageWorkflowUtilities.RunMaximumCoverageAssessmentAsync(
                baseUri,
                BuildStaticCoverageSectionAsync,
                uri => CrawlSiteAsync(uri),
                BuildSpiderCoverageHints,
                () => GetAllDynamicProbes().ToList(),
                RunAdaptiveEndpointSweepAsync,
                progress);
            return await AppendManualPayloadDirectRequestsIfEnabledAsync(baseUri, report);
        }

        private Task<string> BuildStaticCoverageSectionAsync(Uri baseUri)
            => CoverageWorkflowUtilities.BuildStaticCoverageSectionAsync(baseUri, TryFetchOpenApiSnapshotAsync);

        private Task<OpenApiSnapshot?> TryFetchOpenApiSnapshotAsync(Uri baseUri) =>
            OpenApiSnapshotUtilities.TryFetchOpenApiSnapshotAsync(baseUri, GetOpenApiInputRaw(), SafeMetadataSendAsync);

        private async Task<IReadOnlyList<ApiEndpointDescriptor>?> TryFetchEndpointMetadataAsync(Uri baseUri)
        {
            var endpointUri = new Uri(baseUri, "/_apitester/endpoints");
            var response = await SafeMetadataSendAsync(() => new HttpRequestMessage(HttpMethod.Get, endpointUri));
            if (response is null || !response.IsSuccessStatusCode)
            {
                return null;
            }

            var raw = await ReadBodyAsync(response);
            if (string.IsNullOrWhiteSpace(raw))
            {
                return null;
            }

            try
            {
                var parsed = System.Text.Json.JsonSerializer.Deserialize<List<ApiEndpointDescriptor>>(
                    raw,
                    new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                return parsed;
            }
            catch
            {
                return null;
            }
        }

        private async Task<OpenApiProbeContext> GetOpenApiProbeContextAsync(Uri baseUri)
        {
            var overrideRaw = GetOpenApiInputRaw();
            var resolution = await OpenApiProbeContextUtilities.ResolveAsync(
                baseUri,
                overrideRaw,
                IsOpenApiRouteScopeSelected(),
                IsSpiderRouteScopeSelected(),
                IsTypeAwareModeEnabled(),
                _openApiProbeContextCache,
                _lastOpenApiInputRaw,
                TryFetchOpenApiSnapshotAsync,
                TryFetchEndpointMetadataAsync);

            _lastOpenApiInputRaw = resolution.LastOpenApiInputRaw;
            return resolution.Context;
        }

        private void TriggerHeadlessAutoRunIfEnabled()
        {
            if (_headlessAutoRunStarted || !RunReportUtilities.IsTruthyEnvironment("API_TESTER_HEADLESS"))
            {
                return;
            }

            _headlessAutoRunStarted = true;
            var action = HeadlessWorkflowUtilities.ResolveHeadlessRunAction(
                Environment.GetEnvironmentVariable("API_TESTER_HEADLESS_ACTION"));

            switch (action)
            {
                case HeadlessRunAction.RunAllFrameworks:
                    OnRunAllFrameworksClicked(this, EventArgs.Empty);
                    break;
                case HeadlessRunAction.RunMaximumCoverage:
                    OnRunMaxCoverageClicked(this, EventArgs.Empty);
                    break;
                case HeadlessRunAction.SpiderSite:
                    OnSpiderSiteClicked(this, EventArgs.Empty);
                    break;
                case HeadlessRunAction.ValidationHarness:
                    OnRunValidationHarnessClicked(this, EventArgs.Empty);
                    break;
                case HeadlessRunAction.PagingSelfTest:
                    OnRunPagingSelfTestClicked(this, EventArgs.Empty);
                    break;
                default:
                    OnRunEverythingClicked(this, EventArgs.Empty);
                    break;
            }
        }

        private void ResetInMemoryRunLog()
        {
            _inMemoryRunLog = string.Empty;
            _captureRunProgressInMemory = false;
            _pagingMode = ResultPagingMode.TextSummary;
            _resultsPage = 1;
        }

        private static string BuildRunDisplaySummary(string title, string timestampUtc, string body) =>
            DiscoveryUtilities.BuildRunDisplaySummary(title, timestampUtc, body);

        private async void OnRunPagingSelfTestClicked(object? sender, EventArgs e)
        {
            SetBusy(true, "Running paging self-test...");
            try
            {
                var report = await RunPagingSelfTestAsync();
                SetResult(report);
                await HeadlessWorkflowUtilities.EmitHeadlessReportAsync(
                    RunReportUtilities.IsTruthyEnvironment("API_TESTER_HEADLESS"),
                    "paging-selftest",
                    report);
            }
            catch (Exception ex)
            {
                var error = $"Paging self-test failed: {ex.Message}";
                SetResult(error);
                await HeadlessWorkflowUtilities.EmitHeadlessReportAsync(
                    RunReportUtilities.IsTruthyEnvironment("API_TESTER_HEADLESS"),
                    "paging-selftest-error",
                    error);
            }
            finally
            {
                SetBusy(false);
                if (RunReportUtilities.IsTruthyEnvironment("API_TESTER_HEADLESS") && RunReportUtilities.IsTruthyEnvironment("API_TESTER_HEADLESS_EXIT"))
                {
                    MainThread.BeginInvokeOnMainThread(() => Microsoft.Maui.Controls.Application.Current?.Quit());
                }
            }
        }

        private static Task<string> RunPagingSelfTestAsync() => PagingDiagnosticsUtilities.RunPagingSelfTestAsync();

        private string GetOpenApiInputRaw()
        {
            return LegacyTestHarnessUtilities.ResolveOpenApiInputRaw(
                OpenApiInputEntry.Text,
                Environment.GetEnvironmentVariable("API_TESTER_OPENAPI_INPUT"));
        }

        private IEnumerable<DynamicProbe> GetAllDynamicProbes()
        {
            var excluded = SuiteCatalogMappings.GetDynamicProbeExcludedMethodNames();
            return DynamicProbeUtilities.BuildDynamicProbes(this, excluded);
        }

        private Task<SpiderResult> CrawlSiteAsync(Uri baseUri, int maxPages = 500, int maxDepth = 5)
        {
            return SpiderWorkflowUtilities.CrawlSiteAsync(
                baseUri,
                maxPages,
                maxDepth,
                IsCiExtrasEnabled(),
                SafeSendAsync,
                async target =>
                {
                    var openApi = await TryFetchOpenApiSnapshotAsync(target);
                    return openApi?.Document;
                });
        }

        private Task<string> RunAdaptiveEndpointSweepAsync(Uri baseUri, IEnumerable<string> discoveredEndpoints, IProgress<string>? progress = null)
        {
            var sweepTests = GetAllDynamicProbes().ToList();
            return SpiderWorkflowUtilities.RunAdaptiveEndpointSweepAsync(baseUri, discoveredEndpoints, sweepTests, progress);
        }

        private static bool IsSameOrigin(Uri baseUri, Uri candidate) =>
        DiscoveryUtilities.IsSameOrigin(baseUri, candidate);

        private static List<string> BuildSpiderCoverageHints(IEnumerable<string> endpoints)
            => DiscoveryUtilities.BuildSpiderCoverageHints(endpoints);

        private static string FormatStatus(HttpResponseMessage? response) => DiscoveryUtilities.FormatStatus(response);

        private static string BuildUnsignedJwt(Dictionary<string, object> payload) =>
            DiscoveryUtilities.BuildUnsignedJwt(payload);

        private static string BuildUnsignedJwtWithCustomHeader(Dictionary<string, object> payload, Dictionary<string, object> header) =>
            DiscoveryUtilities.BuildUnsignedJwtWithCustomHeader(payload, header);

        private static string Base64UrlEncode(string value) => DiscoveryUtilities.Base64UrlEncode(value);

        private async Task<HttpResponseMessage?> SafeSendAsync(Func<HttpRequestMessage> requestFactory)
        {
            return await RequestSendWorkflowUtilities.SafeSendAsync(
                requestFactory,
                GetEffectiveRequestDelayMs(),
                ApplySingleTargetRequestOverridesAsync,
                requestUri =>
                {
                    var violation = IsStrictSingleScopeViolation(requestUri, out var message);
                    return (violation, message);
                },
                _activeAuthProfile.Value,
                request => _httpClient.SendAsync(request),
                () => _auditCaptureContext.Value,
                () => _activeStandardTestKey.Value,
                GetManualPayloadHint);
        }

        private async Task<HttpResponseMessage?> SafeMetadataSendAsync(Func<HttpRequestMessage> requestFactory)
        {
            return await RequestSendWorkflowUtilities.SafeSendAsync(
                requestFactory,
                GetEffectiveRequestDelayMs(),
                _ => Task.CompletedTask,
                _ => (false, string.Empty),
                _activeAuthProfile.Value,
                request => _httpClient.SendAsync(request),
                () => _auditCaptureContext.Value,
                () => _activeStandardTestKey.Value,
                null);
        }

        private string? GetManualPayloadHint()
        {
            if (!RunReportUtilities.IsTruthyEnvironment("API_TESTER_MANUAL_PAYLOAD_OVERRIDE"))
            {
                return null;
            }

            if (!IsManualPayloadModeEnabled())
            {
                return null;
            }

            var raw = ManualPayloadsEditor.Text;
            if (string.IsNullOrWhiteSpace(raw))
            {
                raw = Environment.GetEnvironmentVariable("API_TESTER_MANUAL_PAYLOADS");
            }

            if (string.IsNullOrWhiteSpace(raw))
            {
                return null;
            }

            var lines = raw.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var line in lines)
            {
                if (line.StartsWith("override:", StringComparison.OrdinalIgnoreCase) ||
                    line.StartsWith("route:", StringComparison.OrdinalIgnoreCase))
                {
                    var value = line[(line.IndexOf(':') + 1)..].Trim();
                    return string.IsNullOrWhiteSpace(value) ? null : value;
                }
            }

            return null;
        }

        private Task ApplySingleTargetRequestOverridesAsync(HttpRequestMessage request)
            => RequestOverrideWorkflowUtilities.ApplySingleTargetRequestOverridesAsync(
                request,
                GetRunScopeMode(),
                () => TryGetConfiguredTargetUriForOverrides(out var configured) ? configured : null,
                TryGetAutomaticSingleTargetOperationProfileAsync,
                GetSelectedPayloadLocation(),
                GetSelectedOperationOverride(),
                ShouldApplyManualSingleTargetPayloadOverrides(),
                IsSameOrigin,
                RequestContractPipeline.PathsMatchForScope);

        private Task<OpenApiOperationProfile?> TryGetAutomaticSingleTargetOperationProfileAsync(Uri configuredTarget)
            => RequestOverrideWorkflowUtilities.TryGetAutomaticSingleTargetOperationProfileAsync(
                configuredTarget,
                IsTypeAwareModeEnabled(),
                GetOpenApiInputRaw(),
                IsOpenApiRouteScopeSelected(),
                IsSpiderRouteScopeSelected(),
                GetOpenApiProbeContextAsync,
                IsSameOrigin,
                RequestContractPipeline.PathsMatchForScope);

        private bool ShouldApplyManualSingleTargetPayloadOverrides()
            => ScanOptionUtilities.ShouldApplyManualSingleTargetPayloadOverrides(
                IsTypeAwareModeEnabled(),
                GetOpenApiInputRaw(),
                IsOpenApiRouteScopeSelected());

        private bool TryGetConfiguredTargetUriForOverrides(out Uri uri)
            => ScanOptionUtilities.TryResolveConfiguredTargetUriForOverrides(
                UrlEntry.Text,
                Environment.GetEnvironmentVariable("API_TESTER_TARGET_URL"),
                Environment.GetEnvironmentVariable("API_TESTER_URL"),
                out uri);

        private HttpMethod? GetSelectedOperationOverride()
            => ScanOptionUtilities.ResolveOperationOverride(TypeAwareModePicker.SelectedItem?.ToString());

        private PayloadLocation GetSelectedPayloadLocation() =>
            ScanOptionUtilities.ResolvePayloadLocation(PayloadLocationPicker.SelectedItem?.ToString());
        private bool IsStrictSingleScopeViolation(Uri? requestUri, out string message)
            => RequestExecutionUtilities.IsStrictSingleScopeViolation(
                _strictSingleTargetMode.Value,
                _strictSingleBaseUri.Value,
                requestUri,
                RequestContractPipeline.PathsMatchForScope,
                out message);

        private static Task<string> ReadBodyAsync(HttpResponseMessage? response) =>
            HttpEvidenceUtilities.ReadBodyAsync(response);

        private static bool ContainsAny(string input, params string[] markers) =>
            TestResultUtilities.ContainsAny(input, markers);

        private static string TryGetHeader(HttpResponseMessage response, string headerName) =>
            TestResultUtilities.TryGetHeader(response, headerName);

        private static bool HasHeader(HttpResponseMessage response, string headerName) =>
            TestResultUtilities.HasHeader(response, headerName);

        private static Uri AppendQuery(Uri baseUri, IDictionary<string, string> additions) =>
            TestResultUtilities.AppendQuery(baseUri, additions);

        private static Uri AppendPathSegment(Uri baseUri, string segment) =>
            UriMutationUtilities.AppendPathSegment(baseUri, segment);

        private static bool IsRoutePlaceholderSegment(string segment) =>
            UriMutationUtilities.IsRoutePlaceholderSegment(segment);

        private static Dictionary<string, string> ParseQuery(string query) =>
            UriMutationUtilities.ParseQuery(query);

        private static string BuildQuery(Dictionary<string, string> values) =>
            UriMutationUtilities.BuildQuery(values);

        private static string FormatSection(string sectionName, Uri uri, IEnumerable<string> findings) =>
            TestResultUtilities.FormatSection(sectionName, uri, findings);

        private ScanOptions BuildCoreScanOptions(Uri target)
        {
            var selectedMethod = GetSelectedOperationOverride();
            return new ScanOptions(
                target,
                "single",
                "txt",
                "all",
                "(all)",
                GetOpenApiInputRaw(),
                StreamLogs: false,
                MethodOverride: selectedMethod?.Method ?? "auto",
                PayloadLocation: GetSelectedPayloadLocation().ToString().ToLowerInvariant(),
                HttpTrace: false);
        }

        private Task<string> RunSharedSecurityHeadersSectionAsync(Uri baseUri) => _logic.RunSecurityHeadersSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedCorsSectionAsync(Uri baseUri) => _logic.RunCorsSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedHttpMethodsSectionAsync(Uri baseUri) => _logic.RunHttpMethodsSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedSqlInjectionSectionAsync(Uri baseUri) => _logic.RunSqlInjectionSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedXssSectionAsync(Uri baseUri) => _logic.RunXssSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedSsrfSectionAsync(Uri baseUri) => _logic.RunSsrfSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedRateLimitSectionAsync(Uri baseUri) => _logic.RunRateLimitSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedInformationDisclosureSectionAsync(Uri baseUri) => _logic.RunInformationDisclosureSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedTransportSecuritySectionAsync(Uri baseUri) => _logic.RunTransportSecuritySectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedErrorHandlingLeakageSectionAsync(Uri baseUri) => _logic.RunErrorHandlingLeakageSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedAuthAndAccessControlSectionAsync(Uri baseUri, string? _ = null) => _logic.RunAuthAndAccessControlSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedBrokenAuthenticationSectionAsync(Uri baseUri) => _logic.RunBrokenAuthenticationSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedBrokenFunctionLevelAuthorizationSectionAsync(Uri baseUri) => _logic.RunBrokenFunctionLevelAuthorizationSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedBrokenObjectPropertyLevelAuthorizationSectionAsync(Uri baseUri) => _logic.RunBrokenObjectPropertyLevelAuthorizationSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedCrossTenantDataLeakageSectionAsync(Uri baseUri) => _logic.RunCrossTenantDataLeakageSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedBolaSectionAsync(Uri baseUri) => _logic.RunBolaSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedCookieSecurityFlagsSectionAsync(Uri baseUri) => _logic.RunCookieSecurityFlagsSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedContentTypeValidationSectionAsync(Uri baseUri) => _logic.RunContentTypeValidationSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedImproperInventoryManagementSectionAsync(Uri baseUri) => _logic.RunImproperInventoryManagementSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private Task<string> RunSharedIdempotencyReplaySectionAsync(Uri baseUri) => _logic.RunIdempotencyReplaySectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

        private void SetBusy(bool busy, string? message = null)
        {
            if (!MainThread.IsMainThread)
            {
                MainThread.BeginInvokeOnMainThread(() => SetBusy(busy, message));
                return;
            }

            BusyIndicator.IsVisible = busy;
            BusyIndicator.IsRunning = busy;
            BusyLabel.IsVisible = busy;
            BusyLabel.Text = string.IsNullOrWhiteSpace(message) ? "Working..." : message;

            if (!string.IsNullOrWhiteSpace(message))
            {
                if (_captureRunProgressInMemory)
                {
                    _rawResultsText = message;
                    _resultsPage = 1;
                    ApplyResultView();
                    return;
                }

                _rawResultsText = message;
                ApplyResultView();
            }
        }

        private void SetResult(string value)
        {
            if (!MainThread.IsMainThread)
            {
                MainThread.BeginInvokeOnMainThread(() => SetResult(value));
                return;
            }

            _rawResultsText = value ?? string.Empty;
            _resultsPage = 1;
            ApplyResultView();
            SemanticScreenReader.Announce("Security test completed.");
        }

        private void AppendRunLogSection(string title, string body)
        {
            var append = ResultPagingWorkflowUtilities.AppendRunLogSection(
                _inMemoryRunLog,
                title,
                body,
                ResultsPageLineCount,
                DateTime.UtcNow);
            _inMemoryRunLog = append.RunLog;
            _pagingMode = ResultPagingMode.RunLogPaged;
            _rawResultsText = _inMemoryRunLog;
            _resultsPage = append.ResultsPage;
            ApplyResultView();
        }

        private void AppendRunProgress(string message)
        {
            var updated = ResultPagingWorkflowUtilities.AppendRunProgress(_inMemoryRunLog, message);
            if (string.Equals(updated, _inMemoryRunLog, StringComparison.Ordinal))
            {
                return;
            }

            _inMemoryRunLog = updated;
            _rawResultsText = _inMemoryRunLog;
            _resultsPage = int.MaxValue;
            ApplyResultView();
        }

        private void SetProgressResult(string? value)
        {
            if (!MainThread.IsMainThread)
            {
                MainThread.BeginInvokeOnMainThread(() => SetProgressResult(value));
                return;
            }

            _rawResultsText = value ?? string.Empty;
            _resultsPage = 1;
            ApplyResultView();
        }

        private void OnResultViewFilterChanged(object? sender, EventArgs e)
        {
            ApplyResultView();
        }

        private async void ApplyResultView()
        {
            if (!MainThread.IsMainThread)
            {
                MainThread.BeginInvokeOnMainThread(ApplyResultView);
                return;
            }

            var renderVersion = Interlocked.Increment(ref _resultRenderVersion);
            var raw = _rawResultsText ?? string.Empty;
            if (_pagingMode == ResultPagingMode.CorpusPaged || _pagingMode == ResultPagingMode.FunctionMapPaged)
            {
                _renderedResultsText = raw;
                ApplyResultsPageView();
                return;
            }
            if (_pagingMode == ResultPagingMode.RunLogPaged)
            {
                _renderedResultsText = _inMemoryRunLog ?? string.Empty;
                ApplyResultsPageView();
                return;
            }

            var shouldUsePrettyFormatting = raw.Length <= PrettyResultFormattingMaxChars;
            var rendered = await Task.Run(() =>
            {
                var normalized = ResultPresentation.NormalizeResultFormatting(raw);
                if (!shouldUsePrettyFormatting)
                {
                    return normalized;
                }

                return ResultPresentation.BuildReadableResults(normalized);
            });

            if (renderVersion != _resultRenderVersion)
            {
                return;
            }

            _renderedResultsText = rendered;
            ApplyResultsPageView();
        }

        private void ApplyResultsPageView()
        {
            var page = ResultPagingWorkflowUtilities.BuildResultsPageView(
                _pagingMode,
                _renderedResultsText ?? string.Empty,
                _inMemoryRunLog ?? string.Empty,
                _resultsPage,
                ResultsPageLineCount);
            _resultsPage = page.CurrentPage;
            ResultsEditor.Text = page.Text;
            ResultsPageLabel.Text = page.Label;
            PrevPageButton.IsEnabled = page.PrevEnabled;
            NextPageButton.IsEnabled = page.NextEnabled;
        }

        private bool IsResultsPagingActive()
        {
            return ResultPagingWorkflowUtilities.IsResultsPagingActive(
                _pagingMode,
                _renderedResultsText ?? string.Empty,
                _inMemoryRunLog ?? string.Empty,
                ResultsPageLineCount);
        }

        private static void AnnounceStatus(string message)
        {
            if (!MainThread.IsMainThread)
            {
                MainThread.BeginInvokeOnMainThread(() => AnnounceStatus(message));
                return;
            }

            SemanticScreenReader.Announce(message);
        }
    }
}







