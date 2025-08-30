// Package cli provides command-line interface implementation for cryptkeeper.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"cryptkeeper/internal/core"
	"cryptkeeper/internal/modules/sysinfo"
	"cryptkeeper/internal/modules/win_ads"
	"cryptkeeper/internal/modules/win_amcache"
	"cryptkeeper/internal/modules/win_applications"
	"cryptkeeper/internal/modules/win_bits"
	"cryptkeeper/internal/modules/win_browser"
	"cryptkeeper/internal/modules/win_certificates"
	"cryptkeeper/internal/modules/win_evtx"
	"cryptkeeper/internal/modules/win_fileshares"
	"cryptkeeper/internal/modules/win_firewall_net"
	"cryptkeeper/internal/modules/win_iis"
	"cryptkeeper/internal/modules/win_jumplists"
	"cryptkeeper/internal/modules/win_kerberos"
	"cryptkeeper/internal/modules/win_lnk"
	"cryptkeeper/internal/modules/win_logon"
	"cryptkeeper/internal/modules/win_lsa"
	"cryptkeeper/internal/modules/win_memory_process"
	"cryptkeeper/internal/modules/win_mft"
	"cryptkeeper/internal/modules/win_modern"
	"cryptkeeper/internal/modules/win_networkinfo"
	"cryptkeeper/internal/modules/win_persistence"
	"cryptkeeper/internal/modules/win_prefetch"
	"cryptkeeper/internal/modules/win_rdp"
	"cryptkeeper/internal/modules/win_recyclebin"
	"cryptkeeper/internal/modules/win_registry"
	"cryptkeeper/internal/modules/win_services_drivers"
	"cryptkeeper/internal/modules/win_signatures"
	"cryptkeeper/internal/modules/win_srum"
	"cryptkeeper/internal/modules/win_systemconfig"
	"cryptkeeper/internal/modules/win_tasks"
	"cryptkeeper/internal/modules/win_tokens"
	"cryptkeeper/internal/modules/win_trustedinstaller"
	"cryptkeeper/internal/modules/win_usb"
	"cryptkeeper/internal/modules/win_usn"
	"cryptkeeper/internal/modules/win_vss"
	"cryptkeeper/internal/modules/win_wmi"
	"cryptkeeper/internal/parse"
	"cryptkeeper/internal/schema"

	"github.com/spf13/cobra"
)

var (
	// Existing flags
	since     string
	encryptAge string
	
	// New flags for the expanded functionality
	parallel      int
	moduleTimeout time.Duration
	out           string
	keepTmp       bool
)

// harvestCmd represents the harvest command.
var harvestCmd = &cobra.Command{
	Use:   "harvest",
	Short: "Collect system artifacts and package them securely",
	Long: `The harvest command runs collection modules to gather system artifacts,
packages them into a compressed archive, and optionally encrypts the result
using age public key encryption.`,
	RunE: runHarvest,
}

func init() {
	// Define flags
	harvestCmd.Flags().StringVar(&since, "since", "", "RFC3339 timestamp or duration like 7d, 72h, 15m, 30s, 2w")
	harvestCmd.Flags().IntVar(&parallel, "parallel", 4, "maximum concurrent modules (1-64)")
	harvestCmd.Flags().DurationVar(&moduleTimeout, "module-timeout", 60*time.Second, "per-module timeout")
	harvestCmd.Flags().StringVar(&encryptAge, "encrypt-age", "", "Age public key for encryption (must start with age1)")
	harvestCmd.Flags().StringVar(&out, "out", "", "output directory for final archive (default: temp directory)")
	harvestCmd.Flags().BoolVar(&keepTmp, "keep-tmp", false, "keep temporary artifacts directory for debugging")
}

func runHarvest(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	now := time.Now()
	
	// Create logger for minimal stderr output
	logger := log.New(os.Stderr, "", log.LstdFlags)
	
	// Validate and clamp parallelism
	if parallel < 1 {
		parallel = 1
	}
	if parallel > 64 {
		parallel = 64
	}
	
	// Validate module timeout
	if moduleTimeout <= 0 {
		return fmt.Errorf("module-timeout must be positive")
	}
	
	// Validate age public key if provided
	var agePublicKey string
	var ageRecipientSet bool
	if encryptAge != "" {
		if err := core.ValidateAgePublicKey(encryptAge); err != nil {
			return fmt.Errorf("invalid --encrypt-age: %w", err)
		}
		agePublicKey = encryptAge
		ageRecipientSet = true
	}
	
	// Parse and normalize since flag (for future use)
	sinceNormalized, sinceWasSet, err := parse.NormalizeSince(since, now)
	if err != nil {
		return err
	}
	
	// Get hostname for archive naming
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	
	// Create temporary artifacts directory
	artifactsDir, err := core.CreateTempDir()
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	
	// Determine output directory for final archive
	var outDir string
	if out == "" {
		// Use the parent directory of artifacts to avoid including archive in itself
		outDir = filepath.Dir(artifactsDir)
		logger.Printf("Using temporary output directory: %s", outDir)
	} else {
		// Use specified directory
		var err error
		outDir, err = filepath.Abs(out)
		if err != nil {
			return fmt.Errorf("failed to resolve output directory: %w", err)
		}
		
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}
	
	// Set up cleanup of temp directory unless --keep-tmp is set
	if !keepTmp {
		defer func() {
			if err := core.RemoveTempDir(artifactsDir); err != nil {
				log.Printf("Warning: failed to clean up temporary directory %s: %v", artifactsDir, err)
			}
		}()
	}
	
	// Create run orchestrator
	run := core.NewRun(parallel, moduleTimeout, artifactsDir, core.SystemClock{}, logger)
	
	// Register modules
	sysInfoModule := sysinfo.NewSysInfo()
	run.Register(sysInfoModule)
	
	winEvtxModule := win_evtx.NewWinEvtx()
	// Pass since time to WinEvtx module if available
	if sinceWasSet && sinceNormalized != "" {
		winEvtxModule.SetSinceTime(sinceNormalized)
	}
	run.Register(winEvtxModule)
	
	winRegistryModule := win_registry.NewWinRegistry()
	run.Register(winRegistryModule)
	
	winPrefetchModule := win_prefetch.NewWinPrefetch()
	run.Register(winPrefetchModule)
	
	winAmcacheModule := win_amcache.NewWinAmcache()
	run.Register(winAmcacheModule)
	
	winJumpListsModule := win_jumplists.NewWinJumpLists()
	run.Register(winJumpListsModule)
	
	winLNKModule := win_lnk.NewWinLNK()
	run.Register(winLNKModule)
	
	winSRUMModule := win_srum.NewWinSRUM()
	run.Register(winSRUMModule)
	
	winBITSModule := win_bits.NewWinBITS()
	run.Register(winBITSModule)
	
	winTasksModule := win_tasks.NewWinTasks()
	run.Register(winTasksModule)
	
	winServicesDriversModule := win_services_drivers.NewWinServicesDrivers()
	run.Register(winServicesDriversModule)
	
	winWMIModule := win_wmi.NewWinWMI()
	run.Register(winWMIModule)
	
	winFirewallNetModule := win_firewall_net.NewWinFirewallNet()
	run.Register(winFirewallNetModule)
	
	winRDPModule := win_rdp.NewWinRDP()
	run.Register(winRDPModule)
	
	winUSBModule := win_usb.NewWinUSB()
	run.Register(winUSBModule)
	
	winBrowserModule := win_browser.NewWinBrowser()
	run.Register(winBrowserModule)
	
	winRecycleBinModule := win_recyclebin.NewWinRecycleBin()
	run.Register(winRecycleBinModule)
	
	winIISModule := win_iis.NewWinIIS()
	run.Register(winIISModule)

	// Register new artifact collection modules
	winNetworkInfoModule := win_networkinfo.NewWinNetworkInfo()
	run.Register(winNetworkInfoModule)

	winSystemConfigModule := win_systemconfig.NewWinSystemConfig()
	run.Register(winSystemConfigModule)

	winMemoryProcessModule := win_memory_process.NewWinMemoryProcess()
	run.Register(winMemoryProcessModule)

	winApplicationsModule := win_applications.NewWinApplications()
	run.Register(winApplicationsModule)

	winPersistenceModule := win_persistence.NewWinPersistence()
	run.Register(winPersistenceModule)

	winModernModule := win_modern.NewWinModern()
	run.Register(winModernModule)

	winMFTModule := win_mft.NewWinMFT()
	run.Register(winMFTModule)

	winUSNModule := win_usn.NewWinUSN()
	run.Register(winUSNModule)

	winVSSModule := win_vss.NewWinVSS()
	run.Register(winVSSModule)

	winFileSharesModule := win_fileshares.NewWinFileShares()
	run.Register(winFileSharesModule)

	winLSAModule := win_lsa.NewWinLSA()
	run.Register(winLSAModule)

	winKerberosModule := win_kerberos.NewWinKerberos()
	run.Register(winKerberosModule)

	winLogonModule := win_logon.NewWinLogon()
	run.Register(winLogonModule)

	winTokensModule := win_tokens.NewWinTokens()
	run.Register(winTokensModule)

	winADSModule := win_ads.NewWinADS()
	run.Register(winADSModule)

	winSignaturesModule := win_signatures.NewWinSignatures()
	run.Register(winSignaturesModule)

	winCertificatesModule := win_certificates.NewWinCertificates()
	run.Register(winCertificatesModule)

	winTrustedInstallerModule := win_trustedinstaller.NewWinTrustedInstaller()
	run.Register(winTrustedInstallerModule)
	
	// Collect module names for output
	modulesRun := []string{
		sysInfoModule.Name(), 
		winEvtxModule.Name(), 
		winRegistryModule.Name(),
		winPrefetchModule.Name(),
		winAmcacheModule.Name(),
		winJumpListsModule.Name(),
		winLNKModule.Name(),
		winSRUMModule.Name(),
		winBITSModule.Name(),
		winTasksModule.Name(),
		winServicesDriversModule.Name(),
		winWMIModule.Name(),
		winFirewallNetModule.Name(),
		winRDPModule.Name(),
		winUSBModule.Name(),
		winBrowserModule.Name(),
		winRecycleBinModule.Name(),
		winIISModule.Name(),
		// New artifact collection modules
		winNetworkInfoModule.Name(),
		winSystemConfigModule.Name(),
		winMemoryProcessModule.Name(),
		winApplicationsModule.Name(),
		winPersistenceModule.Name(),
		winModernModule.Name(),
		winMFTModule.Name(),
		winUSNModule.Name(),
		winVSSModule.Name(),
		winFileSharesModule.Name(),
		winLSAModule.Name(),
		winKerberosModule.Name(),
		winLogonModule.Name(),
		winTokensModule.Name(),
		winADSModule.Name(),
		winSignaturesModule.Name(),
		winCertificatesModule.Name(),
		winTrustedInstallerModule.Name(),
	}
	
	// Execute all modules
	logger.Printf("Starting collection with %d modules, %d parallel, %s timeout", 
		len(modulesRun), parallel, moduleTimeout)
	
	results, collectErr := run.CollectAll(ctx)
	if collectErr != nil {
		logger.Printf("Collection completed with errors: %v", collectErr)
	} else {
		logger.Printf("Collection completed successfully")
	}
	
	// Bundle and optionally encrypt the artifacts
	logger.Printf("Creating archive...")
	packageMeta, err := core.BundleAndMaybeEncrypt(
		ctx, 
		artifactsDir, 
		outDir, 
		hostname, 
		now, 
		agePublicKey,
	)
	if err != nil {
		return fmt.Errorf("failed to create archive: %w", err)
	}
	
	logger.Printf("Archive created: %s", packageMeta.Path)
	
	// Build output structure
	finalArtifactsDir := artifactsDir
	if !keepTmp {
		finalArtifactsDir = ""  // Indicate it was removed
	}
	
	output := schema.NewRunOutput(
		finalArtifactsDir,
		packageMeta.Path,
		packageMeta.Encrypted,
		ageRecipientSet,
		parallel,
		moduleTimeout,
		modulesRun,
		results,
		packageMeta.FileCount,
		packageMeta.BytesWritten,
		now,
	)
	
	// Set since fields if provided
	if sinceWasSet {
		output.SetSince(since, sinceNormalized)
	}
	
	// Marshal and output JSON with pretty formatting
	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal output JSON: %w", err)
	}
	
	fmt.Println(string(jsonBytes))
	
	// Return collection error as the command result, if any
	return collectErr
}