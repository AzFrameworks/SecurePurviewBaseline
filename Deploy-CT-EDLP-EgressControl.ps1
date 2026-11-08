#Requires -Version 5.1
<#
.SYNOPSIS
    CT-EDLP Egress Control — Microsoft Purview Endpoint DLP Deployment Script

.DESCRIPTION
    Deploys 11 Endpoint DLP policies (CT-EDLP-01 through CT-EDLP-11) that block
    egress of sensitivity-labelled documents across all configured channels.
    All policies are created in TestWithoutNotifications (simulate/silent) mode
    by default. Use the policy-selection dialog to adjust per-policy deployment modes.

.NOTES
    Author  : Daniel Metzger
    Version : 1.0.0
    Date    : 2026-10-22
    Requires: ExchangeOnlineManagement module (installed automatically if absent)
              Microsoft Purview Compliance portal admin rights

.DISCLAIMER
    This script is provided as-is, without warranty of any kind, express or implied.
    It has been designed and tested for use in specific environments and may not be
    suitable for all configurations. The author assumes no liability for any damage,
    data loss, service disruption, or unintended policy enforcement resulting from
    its use. Review all settings and test in a non-production environment before
    deploying to production. All policies are created in simulation mode by default;
    the operator is solely responsible for any decision to switch policies to
    enforcement mode.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ============================================================
#region  FUNCTION: Show-MailboxDialog
# ============================================================
function Show-MailboxDialog {
    $form = New-Object System.Windows.Forms.Form
    $form.Text            = 'CT-EDLP — Incident Mailbox'
    $form.Size            = New-Object System.Drawing.Size(480, 220)
    $form.StartPosition   = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox     = $false
    $form.MinimizeBox     = $false
    $form.Font            = New-Object System.Drawing.Font('Segoe UI', 9)

    $lblInstruct = New-Object System.Windows.Forms.Label
    $lblInstruct.Text     = 'Enter the mailbox address that will receive DLP incident reports and alerts:'
    $lblInstruct.Location = New-Object System.Drawing.Point(16, 16)
    $lblInstruct.Size     = New-Object System.Drawing.Size(440, 36)
    $form.Controls.Add($lblInstruct)

    $txtMailbox = New-Object System.Windows.Forms.TextBox
    $txtMailbox.Location      = New-Object System.Drawing.Point(16, 60)
    $txtMailbox.Size          = New-Object System.Drawing.Size(440, 24)
    $txtMailbox.PlaceholderText = 'security-alerts@company.com'
    $form.Controls.Add($txtMailbox)

    $lblError = New-Object System.Windows.Forms.Label
    $lblError.Text      = ''
    $lblError.ForeColor = [System.Drawing.Color]::Red
    $lblError.Location  = New-Object System.Drawing.Point(16, 88)
    $lblError.Size      = New-Object System.Drawing.Size(440, 20)
    $form.Controls.Add($lblError)

    $btnContinue = New-Object System.Windows.Forms.Button
    $btnContinue.Text     = 'Continue'
    $btnContinue.Location = New-Object System.Drawing.Point(284, 140)
    $btnContinue.Size     = New-Object System.Drawing.Size(84, 28)
    $btnContinue.DialogResult = [System.Windows.Forms.DialogResult]::None
    $form.Controls.Add($btnContinue)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text           = 'Cancel'
    $btnCancel.Location       = New-Object System.Drawing.Point(376, 140)
    $btnCancel.Size           = New-Object System.Drawing.Size(80, 28)
    $btnCancel.DialogResult   = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton        = $btnCancel
    $form.Controls.Add($btnCancel)

    $emailRegex = '^[^@\s]+@[^@\s]+\.[^@\s]+$'

    $btnContinue.Add_Click({
        $val = $txtMailbox.Text.Trim()
        if ($val -notmatch $emailRegex) {
            $lblError.Text = 'Please enter a valid email address.'
        } else {
            $lblError.Text        = ''
            $form.DialogResult    = [System.Windows.Forms.DialogResult]::OK
            $form.Tag             = $val
            $form.Close()
        }
    })

    $result = $form.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::Cancel) {
        Write-Host 'Deployment cancelled.'
        exit 0
    }
    return $form.Tag
}
#endregion

# ============================================================
#region  FUNCTION: Show-LabelDialog
# ============================================================
function Show-LabelDialog {
    param([object[]]$Labels)

    $form = New-Object System.Windows.Forms.Form
    $form.Text            = 'CT-EDLP — Labels That Trigger Egress Blocks'
    $form.Size            = New-Object System.Drawing.Size(660, 580)
    $form.StartPosition   = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox     = $false
    $form.MinimizeBox     = $false
    $form.Font            = New-Object System.Drawing.Font('Segoe UI', 9)

    $lblInstruct = New-Object System.Windows.Forms.Label
    $lblInstruct.Text     = 'Select which sensitivity labels will trigger egress blocks.'
    $lblInstruct.Location = New-Object System.Drawing.Point(12, 12)
    $lblInstruct.Size     = New-Object System.Drawing.Size(620, 24)
    $form.Controls.Add($lblInstruct)

    $lv = New-Object System.Windows.Forms.ListView
    $lv.Location          = New-Object System.Drawing.Point(12, 44)
    $lv.Size              = New-Object System.Drawing.Size(620, 400)
    $lv.View              = [System.Windows.Forms.View]::Details
    $lv.CheckBoxes        = $true
    $lv.FullRowSelect     = $true
    $lv.GridLines         = $true

    $col1 = New-Object System.Windows.Forms.ColumnHeader
    $col1.Text  = 'Label Name'
    $col1.Width = 350

    $col2 = New-Object System.Windows.Forms.ColumnHeader
    $col2.Text  = 'Parent Label'
    $col2.Width = 240

    $lv.Columns.Add($col1) | Out-Null
    $lv.Columns.Add($col2) | Out-Null

    # Build label lookup for parent name and priority resolution
    $labelByGuid = @{}
    foreach ($lbl in $Labels) { $labelByGuid[$lbl.Guid.ToString()] = $lbl }

    $emptyGuid = [System.Guid]::Empty.ToString()

    # Identify labels that are parents of other labels — these are excluded from the list.
    $parentGuids = @{}
    foreach ($lbl in $Labels) {
        $parentRef = try { $lbl.ParentId.ToString() } catch { $emptyGuid }
        if ($parentRef -ne $emptyGuid -and $labelByGuid.ContainsKey($parentRef)) {
            $parentGuids[$parentRef] = $true
        }
    }

    # Only leaf (non-parent) labels; sort by parent priority then own priority so
    # sublabels appear grouped under their parent.
    $sortedLabels = $Labels | Where-Object { -not $parentGuids.ContainsKey($_.Guid.ToString()) } | Sort-Object {
        $pGuid = try { $_.ParentId.ToString() } catch { $emptyGuid }
        if ($labelByGuid.ContainsKey($pGuid)) { [int]$labelByGuid[$pGuid].Priority } else { [int]$_.Priority }
    }, { [int]$_.Priority }

    foreach ($sl in $sortedLabels) {
        $parentId   = try { $sl.ParentId.ToString() } catch { $emptyGuid }
        $parentName = if ($labelByGuid.ContainsKey($parentId)) { $labelByGuid[$parentId].DisplayName } else { '' }

        $item = New-Object System.Windows.Forms.ListViewItem($sl.DisplayName)
        $item.SubItems.Add($parentName) | Out-Null
        $item.Checked = $false
        $item.Tag     = $sl.Guid.ToString()
        $lv.Items.Add($item) | Out-Null
    }

    $form.Controls.Add($lv)

    $countLbl = New-Object System.Windows.Forms.Label
    $countLbl.Location = New-Object System.Drawing.Point(12, 468)
    $countLbl.Size     = New-Object System.Drawing.Size(300, 20)

    $selectableCount = $sortedLabels.Count
    $updateCount = {
        $checked = @($lv.Items | Where-Object { $_.Checked }).Count
        $countLbl.Text = "$checked of $selectableCount labels selected"
    }
    & $updateCount
    $form.Controls.Add($countLbl)

    $lv.Add_ItemChecked({ & $updateCount })

    $btnSelectAll = New-Object System.Windows.Forms.Button
    $btnSelectAll.Text     = 'Select All'
    $btnSelectAll.Location = New-Object System.Drawing.Point(12, 498)
    $btnSelectAll.Size     = New-Object System.Drawing.Size(90, 28)
    $btnSelectAll.Add_Click({
        foreach ($it in $lv.Items) { $it.Checked = $true }
    })
    $form.Controls.Add($btnSelectAll)

    $btnClearAll = New-Object System.Windows.Forms.Button
    $btnClearAll.Text     = 'Clear All'
    $btnClearAll.Location = New-Object System.Drawing.Point(110, 498)
    $btnClearAll.Size     = New-Object System.Drawing.Size(90, 28)
    $btnClearAll.Add_Click({
        foreach ($it in $lv.Items) { $it.Checked = $false }
    })
    $form.Controls.Add($btnClearAll)

    $btnContinue = New-Object System.Windows.Forms.Button
    $btnContinue.Text     = 'Continue'
    $btnContinue.Location = New-Object System.Drawing.Point(464, 498)
    $btnContinue.Size     = New-Object System.Drawing.Size(84, 28)
    $form.Controls.Add($btnContinue)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text         = 'Cancel'
    $btnCancel.Location     = New-Object System.Drawing.Point(556, 498)
    $btnCancel.Size         = New-Object System.Drawing.Size(76, 28)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton      = $btnCancel
    $form.Controls.Add($btnCancel)

    $btnContinue.Add_Click({
        $checked = @($lv.Items | Where-Object { $_.Checked })
        if ($checked.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                'Please select at least one sensitivity label, or click Cancel to abort deployment.',
                'No Labels Selected',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })

    $result = $form.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::Cancel) {
        Write-Host 'Deployment cancelled.'
        exit 0
    }

    $selection = @{}
    foreach ($it in $lv.Items) {
        if ($it.Checked) { $selection[$it.Tag] = $it.Text }
    }
    return $selection
}
#endregion

# ============================================================
#region  POLICY CATALOG
# ============================================================
$policyCatalog = @(
    [PSCustomObject]@{
        GroupLabel = 'Device Egress'
        GroupDesc  = 'Controls egress via physical and local device channels on managed endpoints.'
        Entries    = @(
            [PSCustomObject]@{
                Name        = 'CT-EDLP-01-RemovableMedia'
                Label       = 'CT-EDLP-01 — Removable Media'
                DefaultMode = 'TestWithoutNotifications'
                Description = 'Blocks copying sensitivity-labelled files to removable media (USB drives, SD cards, external hard drives). Prevents physical data exfiltration via portable storage devices connected to managed endpoints.'
            },
            [PSCustomObject]@{
                Name        = 'CT-EDLP-02-Print'
                Label       = 'CT-EDLP-02 — Print'
                DefaultMode = 'TestWithoutNotifications'
                Description = 'Blocks printing of sensitivity-labelled documents on managed endpoints, including printing to PDF. Prevents hard-copy or file-based exfiltration via the print subsystem.'
            },
            [PSCustomObject]@{
                Name        = 'CT-EDLP-03-Clipboard'
                Label       = 'CT-EDLP-03 — Clipboard Copy'
                DefaultMode = 'TestWithoutNotifications'
                Description = 'Blocks clipboard copy operations on sensitivity-labelled content. Prevents users from pasting protected data into unauthorized applications or documents.'
            },
            [PSCustomObject]@{
                Name        = 'CT-EDLP-04-Bluetooth'
                Label       = 'CT-EDLP-04 — Bluetooth Transfer'
                DefaultMode = 'TestWithoutNotifications'
                Description = 'Blocks transfer of sensitivity-labelled files via Bluetooth. Covers Bluetooth file transfer utilities and OS-level Bluetooth sharing on managed Windows endpoints.'
            },
            [PSCustomObject]@{
                Name        = 'CT-EDLP-05-RDPCopy'
                Label       = 'CT-EDLP-05 — RDP Copy'
                DefaultMode = 'TestWithoutNotifications'
                Description = 'Blocks clipboard and drive redirection of sensitivity-labelled content during Remote Desktop Protocol sessions. Prevents data leaving the managed environment via RDP-connected clients.'
            },
            [PSCustomObject]@{
                Name        = 'CT-EDLP-06-NetworkShare'
                Label       = 'CT-EDLP-06 — Network Share Copy'
                DefaultMode = 'TestWithoutNotifications'
                Description = 'Blocks copying sensitivity-labelled files to network shares (SMB paths). Restricts lateral movement of protected content to unmanaged or non-compliant file server locations.'
            }
        )
    },
    [PSCustomObject]@{
        GroupLabel = 'Browser & Cloud Egress'
        GroupDesc  = 'Controls egress via web browsers and cloud storage services.'
        Entries    = @(
            [PSCustomObject]@{
                Name        = 'CT-EDLP-07-WebmailUpload'
                Label       = 'CT-EDLP-07 — Webmail Upload'
                DefaultMode = 'TestWithoutNotifications'
                Description = 'Blocks browser-based upload of sensitivity-labelled files to personal webmail services (Gmail, Outlook.com, Yahoo Mail, etc.) classified in the Cloud Service Domains list. Requires Cloud Service Domain configuration in Endpoint DLP settings before enforcement.'
            },
            [PSCustomObject]@{
                Name        = 'CT-EDLP-08-CloudStorage'
                Label       = 'CT-EDLP-08 — Cloud Storage Upload'
                DefaultMode = 'TestWithoutNotifications'
                Description = 'Blocks upload of sensitivity-labelled files to unsanctioned cloud storage services (Dropbox, Box, personal Google Drive, etc.) classified in the Cloud Service Domains list. Requires Cloud Service Domain configuration in Endpoint DLP settings before enforcement.'
            },
            [PSCustomObject]@{
                Name        = 'CT-EDLP-09-GenerativeAI'
                Label       = 'CT-EDLP-09 — Generative AI Websites'
                DefaultMode = 'TestWithoutNotifications'
                Description = 'Blocks pasting or uploading sensitivity-labelled content to generative AI websites (ChatGPT, Gemini, Copilot.com, etc.). Requires the Microsoft Purview AI Hub feature and DLP for AI Apps license. Verify feature availability before enforcement.'
            }
        )
    },
    [PSCustomObject]@{
        GroupLabel = 'Application Egress'
        GroupDesc  = 'Controls egress via unmanaged or restricted desktop applications.'
        Entries    = @(
            [PSCustomObject]@{
                Name        = 'CT-EDLP-10-UnallowedApps'
                Label       = 'CT-EDLP-10 — Unallowed Applications'
                DefaultMode = 'TestWithoutNotifications'
                Description = 'Blocks access to sensitivity-labelled files by applications listed in the Restricted App Groups. Prevents unmanaged or unauthorized applications from opening, reading, or copying protected content. Requires Restricted App Groups configuration in Endpoint DLP settings.'
            }
        )
    },
    [PSCustomObject]@{
        GroupLabel = 'Communication Egress'
        GroupDesc  = 'Controls egress via collaboration and communication platforms.'
        Entries    = @(
            [PSCustomObject]@{
                Name        = 'CT-EDLP-11-Exchange'
                Label       = 'CT-EDLP-11 — Exchange Email (External)'
                DefaultMode = 'TestWithoutNotifications'
                Description = 'Blocks sending sensitivity-labelled content via Exchange email to external recipients (NotInOrganization scope). Does not affect internal email. Recommended as the first policy to move to Enforce mode after the simulation period.'
            }
        )
    }
)
#endregion

# ============================================================
#region  FUNCTION: Show-PolicyDialog
# ============================================================
function Show-PolicyDialog {
    param([array]$Catalog)

    $form = New-Object System.Windows.Forms.Form
    $form.Text            = 'CT-EDLP — Select and Configure Policies'
    $form.Size            = New-Object System.Drawing.Size(820, 592)
    $form.StartPosition   = 'CenterScreen'
    $form.FormBorderStyle = 'Sizable'
    $form.MinimumSize     = New-Object System.Drawing.Size(820, 592)
    $form.Font            = New-Object System.Drawing.Font('Segoe UI', 9)

    $ctx = [PSCustomObject]@{
        UpdatingCheck = $false
    }

    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = [System.Windows.Forms.DockStyle]::Fill
    $form.Controls.Add($split)
    $form.Add_Load({
        $split.Panel1MinSize    = 200
        $split.Panel2MinSize    = 300
        $split.SplitterDistance = 320
        # Auto-select first rule so the Deployment Mode panel is visible on open
        if ($tree.Nodes.Count -gt 0 -and $tree.Nodes[0].Nodes.Count -gt 0) {
            $tree.SelectedNode = $tree.Nodes[0].Nodes[0]
        }
    })

    # ---- Left panel: TreeView ----
    $tree = New-Object System.Windows.Forms.TreeView
    $tree.Dock         = [System.Windows.Forms.DockStyle]::Fill
    $tree.CheckBoxes   = $true
    $tree.HideSelection = $false
    $split.Panel1.Controls.Add($tree)

    $totalEntries = 0
    foreach ($grp in $Catalog) { $totalEntries += $grp.Entries.Count }

    $boldFont = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)

    foreach ($grp in $Catalog) {
        $gNode          = New-Object System.Windows.Forms.TreeNode($grp.GroupLabel)
        $gNode.NodeFont  = $boldFont
        $gNode.Checked   = $true
        $gNode.Tag       = [PSCustomObject]@{
            IsGroup    = $true
            GroupLabel = $grp.GroupLabel
            GroupDesc  = $grp.GroupDesc
        }
        foreach ($entry in $grp.Entries) {
            $eNode         = New-Object System.Windows.Forms.TreeNode("   `u{2514}  " + $entry.Label)
            $eNode.Checked  = $true
            $eNode.Tag      = [PSCustomObject]@{
                IsGroup     = $false
                Name        = $entry.Name
                Description = $entry.Description
                Label       = $entry.Label
            }
            $gNode.Nodes.Add($eNode) | Out-Null
        }
        $tree.Nodes.Add($gNode) | Out-Null
        $gNode.Expand()
    }

    # ---- Right panel ----
    $pnlRight = New-Object System.Windows.Forms.Panel
    $pnlRight.Dock = [System.Windows.Forms.DockStyle]::Fill
    $split.Panel2.Controls.Add($pnlRight)

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text     = 'Policy Details'
    $lblTitle.Font     = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
    $lblTitle.Location = New-Object System.Drawing.Point(8, 8)
    $lblTitle.Size     = New-Object System.Drawing.Size(440, 26)
    $pnlRight.Controls.Add($lblTitle)

    $pnlSep = New-Object System.Windows.Forms.Panel
    $pnlSep.BackColor = [System.Drawing.Color]::LightGray
    $pnlSep.Location  = New-Object System.Drawing.Point(8, 38)
    $pnlSep.Size      = New-Object System.Drawing.Size(440, 2)
    $pnlRight.Controls.Add($pnlSep)

    $txtDesc = New-Object System.Windows.Forms.RichTextBox
    $txtDesc.Location    = New-Object System.Drawing.Point(8, 46)
    $txtDesc.Size        = New-Object System.Drawing.Size(440, 360)
    $txtDesc.ReadOnly    = $true
    $txtDesc.BackColor   = [System.Drawing.SystemColors]::Control
    $txtDesc.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $txtDesc.Text        = 'Select a policy or group from the tree on the left to view its description.'
    $pnlRight.Controls.Add($txtDesc)

    # AfterSelect — update description panel only; mode is global (set in the bottom bar).
    $tree.Add_AfterSelect({
        $node = $_.Node
        if ($null -eq $node -or $null -eq $node.Tag) { return }
        $tag = $node.Tag
        if (-not $tag.IsGroup) {
            $lblTitle.Text = $tag.Label
            $txtDesc.Text  = $tag.Description
        } else {
            $lblTitle.Text = $tag.GroupLabel
            $txtDesc.Text  = $tag.GroupDesc
        }
    })

    # updateCount scriptblock
    $updateCount = {
        $cnt = 0
        foreach ($gn in $tree.Nodes) {
            foreach ($en in $gn.Nodes) {
                if ($en.Checked) { $cnt++ }
            }
        }
        $countLbl.Text = "$cnt of $totalEntries rules selected"
    }

    # AfterCheck
    $tree.Add_AfterCheck({
        if ($ctx.UpdatingCheck) { return }
        $ctx.UpdatingCheck = $true
        $node = $_.Node
        $tag  = $node.Tag
        if ($null -ne $tag -and $tag.IsGroup) {
            foreach ($child in $node.Nodes) {
                $child.Checked = $node.Checked
            }
        }
        & $updateCount
        $ctx.UpdatingCheck = $false
    })

    # Bottom bar — docked below the SplitContainer
    $pnlBottom = New-Object System.Windows.Forms.Panel
    $pnlBottom.Dock   = [System.Windows.Forms.DockStyle]::Bottom
    $pnlBottom.Height = 70
    $form.Controls.Add($pnlBottom)

    # Row 1: policy count + Select All / Clear All + Continue / Cancel
    $countLbl = New-Object System.Windows.Forms.Label
    $countLbl.Location = New-Object System.Drawing.Point(8, 10)
    $countLbl.Size     = New-Object System.Drawing.Size(390, 20)
    $countLbl.Text     = "$totalEntries of $totalEntries rules selected"
    $pnlBottom.Controls.Add($countLbl)

    $btnSelectAll = New-Object System.Windows.Forms.Button
    $btnSelectAll.Text     = 'Select All'
    $btnSelectAll.Location = New-Object System.Drawing.Point(406, 6)
    $btnSelectAll.Size     = New-Object System.Drawing.Size(84, 26)
    $btnSelectAll.Add_Click({
        $ctx.UpdatingCheck = $true
        foreach ($gn in $tree.Nodes) {
            $gn.Checked = $true
            foreach ($en in $gn.Nodes) { $en.Checked = $true }
        }
        $ctx.UpdatingCheck = $false
        & $updateCount
    })
    $pnlBottom.Controls.Add($btnSelectAll)

    $btnClearAll = New-Object System.Windows.Forms.Button
    $btnClearAll.Text     = 'Clear All'
    $btnClearAll.Location = New-Object System.Drawing.Point(498, 6)
    $btnClearAll.Size     = New-Object System.Drawing.Size(84, 26)
    $btnClearAll.Add_Click({
        $ctx.UpdatingCheck = $true
        foreach ($gn in $tree.Nodes) {
            $gn.Checked = $false
            foreach ($en in $gn.Nodes) { $en.Checked = $false }
        }
        $ctx.UpdatingCheck = $false
        & $updateCount
    })
    $pnlBottom.Controls.Add($btnClearAll)

    $btnContinue = New-Object System.Windows.Forms.Button
    $btnContinue.Text         = 'Continue'
    $btnContinue.Location     = New-Object System.Drawing.Point(620, 6)
    $btnContinue.Size         = New-Object System.Drawing.Size(84, 26)
    $btnContinue.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton        = $btnContinue
    $pnlBottom.Controls.Add($btnContinue)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text         = 'Cancel'
    $btnCancel.Location     = New-Object System.Drawing.Point(712, 6)
    $btnCancel.Size         = New-Object System.Drawing.Size(76, 26)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton      = $btnCancel
    $pnlBottom.Controls.Add($btnCancel)

    $btnCancel.Add_Click({
        Write-Host 'Deployment cancelled.'
        exit 0
    })

    # Row 2: global deployment mode — applies to all selected policies
    $lblMode = New-Object System.Windows.Forms.Label
    $lblMode.Text      = 'Deployment mode:'
    $lblMode.Location  = New-Object System.Drawing.Point(8, 42)
    $lblMode.Size      = New-Object System.Drawing.Size(115, 22)
    $lblMode.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $pnlBottom.Controls.Add($lblMode)

    $rbSimSilent = New-Object System.Windows.Forms.RadioButton
    $rbSimSilent.Text     = 'Simulate — silent'
    $rbSimSilent.Location = New-Object System.Drawing.Point(126, 40)
    $rbSimSilent.Size     = New-Object System.Drawing.Size(140, 22)
    $rbSimSilent.Checked  = $true
    $pnlBottom.Controls.Add($rbSimSilent)

    $rbSimTips = New-Object System.Windows.Forms.RadioButton
    $rbSimTips.Text     = 'Simulate — with tips'
    $rbSimTips.Location = New-Object System.Drawing.Point(269, 40)
    $rbSimTips.Size     = New-Object System.Drawing.Size(148, 22)
    $pnlBottom.Controls.Add($rbSimTips)

    $rbEnforce = New-Object System.Windows.Forms.RadioButton
    $rbEnforce.Text     = 'Enforce'
    $rbEnforce.Location = New-Object System.Drawing.Point(420, 40)
    $rbEnforce.Size     = New-Object System.Drawing.Size(80, 22)
    $pnlBottom.Controls.Add($rbEnforce)

    $result = $form.ShowDialog()

    if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Host 'Deployment cancelled.'
        exit 0
    }

    # Read mode once from the global radio buttons — applies to all selected policies.
    $selectedMode = if ($rbEnforce.Checked) { 'Enable' } elseif ($rbSimTips.Checked) { 'TestWithNotifications' } else { 'TestWithoutNotifications' }

    $config = @{}
    foreach ($gNode in $tree.Nodes) {
        foreach ($eNode in $gNode.Nodes) {
            $eTag = $eNode.Tag
            $config[$eTag.Name] = @{
                Enabled = $eNode.Checked
                Mode    = $selectedMode
            }
        }
    }
    return $config
}
#endregion

# ============================================================
#region  GUI PHASE
# ============================================================
Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '  CT-EDLP Egress Control — Deployment Configuration'         -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host '  Opening configuration dialogs...' -ForegroundColor Gray
Write-Host ''

$IncidentMailbox = Show-MailboxDialog
Write-Host "  Incident mailbox : $IncidentMailbox"
Write-Host ''
#endregion

# ============================================================
#region  SCRIPT SETUP
# ============================================================
$ErrorActionPreference = 'Stop'

$script:pendingActions  = [System.Collections.Generic.List[string]]::new()
$script:createdPolicies = [System.Collections.Generic.List[string]]::new()
$script:createdRules    = [System.Collections.Generic.List[string]]::new()
$script:skippedRules    = [System.Collections.Generic.List[string]]::new()
#endregion

# ============================================================
#region  PREREQUISITES
# ============================================================
function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 60) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 60) -ForegroundColor Cyan
    Write-Host ''
}

Write-Section 'Prerequisites'

# TLS 1.2 — PSGallery rejects connections that negotiate TLS 1.0/1.1.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host '  TLS 1.2 enforced.' -ForegroundColor Green

# NuGet package provider — required by Install-Module.
$nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
if ($null -eq $nuget -or $nuget.Version -lt [Version]'2.8.5.201') {
    Write-Host '  Installing NuGet package provider...' -ForegroundColor Yellow
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
    Write-Host '  NuGet package provider installed.' -ForegroundColor Green
} else {
    Write-Host "  NuGet package provider v$($nuget.Version) found." -ForegroundColor Green
}

# ExchangeOnlineManagement — provides Connect-IPPSSession and all DLP cmdlets.
$modName = 'ExchangeOnlineManagement'
if (-not (Get-Module -ListAvailable -Name $modName)) {
    Write-Host "  Installing $modName module..." -ForegroundColor Yellow
    Install-Module -Name $modName -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
    Write-Host "  $modName installed." -ForegroundColor Green
} else {
    Write-Host "  $modName module found." -ForegroundColor Green
}

Import-Module $modName -ErrorAction Stop

$modVer = (Get-Module $modName).Version
Write-Host "  Module version   : $modVer" -ForegroundColor Gray
#endregion

# ============================================================
#region  IPPS CONNECTION
# ============================================================
Write-Section 'Connecting to Security & Compliance (IPPS)'

function Connect-IPPS {
    param([switch]$UseRPS)
    $p = @{
        ShowBanner = $false
    }
    if ($UseRPS) {
        $cmdMeta = Get-Command Connect-IPPSSession -ErrorAction SilentlyContinue
        if ($null -ne $cmdMeta) {
            $paramNames = $cmdMeta.Parameters.Keys
            if ($paramNames -contains 'UseRPSSession') {
                $p['UseRPSSession'] = $true
            }
        }
    }
    $cmdMeta2 = Get-Command Connect-IPPSSession -ErrorAction SilentlyContinue
    if ($null -ne $cmdMeta2) {
        if ($cmdMeta2.Parameters.Keys -contains 'SkipLoadingFormatData') {
            $p['SkipLoadingFormatData'] = $true
        }
    }
    Connect-IPPSSession @p
}

try {
    Connect-IPPS
    Write-Host '  Connected to IPPS.' -ForegroundColor Green
} catch {
    Write-Warning "  Initial connection failed: $_"
    Write-Host    '  Retrying...' -ForegroundColor Yellow
    Connect-IPPS
    Write-Host '  Connected to IPPS (retry).' -ForegroundColor Green
}

# Verify DLP cmdlets are available
$dlpAvailable = $null -ne (Get-Command Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)
if (-not $dlpAvailable) {
    Write-Host '  DLP cmdlets not available — retrying with UseRPS...' -ForegroundColor Yellow
    Connect-IPPS -UseRPS
    $dlpAvailable = $null -ne (Get-Command Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)
}

if (-not $dlpAvailable) {
    Write-Error @'
  Get-DlpCompliancePolicy is not available after connection.
  Possible causes:
    1. The account lacks Compliance Administrator or Global Administrator role.
    2. The tenant does not have a Microsoft Purview Compliance license.
    3. The ExchangeOnlineManagement module version is outdated — try:
         Update-Module ExchangeOnlineManagement -Force
  Please resolve the above and re-run the script.
'@
    exit 1
}

try {
    $orgDomain = $null
    # Get-OrganizationConfig is Exchange Online-only; use Get-ConnectionInformation which
    # works in both EXO and IPPS (Security & Compliance) sessions.
    $connInfo = Get-ConnectionInformation -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($connInfo -and $connInfo.UserPrincipalName) {
        $orgDomain = $connInfo.UserPrincipalName.Split('@')[1]
    }
    if (-not $orgDomain) {
        $orgCfg    = Get-OrganizationConfig -ErrorAction SilentlyContinue
        $orgDomain = if ($null -ne $orgCfg) { $orgCfg.DefaultAcceptedDomain } else { $null }
    }
    Write-Host "  Tenant domain    : $(if ($orgDomain) { $orgDomain } else { '(unknown)' })" -ForegroundColor Gray
} catch {
    Write-Host '  Could not retrieve tenant domain.' -ForegroundColor Yellow
}
#endregion

# ============================================================
#region  POLICY SELECTION DIALOG
# ============================================================
Write-Section 'Policy Selection'

$deployConfig = Show-PolicyDialog -Catalog $policyCatalog
$_sel = @($deployConfig.Values | Where-Object { $_.Enabled })
Write-Host "  Policies selected : $($_sel.Count) of 11" -ForegroundColor Gray
Write-Host ''
#endregion

# ============================================================
#region  SENSITIVITY LABELS
# ============================================================
Write-Section 'Sensitivity Labels'

Write-Host '  Fetching published sensitivity labels...' -ForegroundColor Gray

$allLabels = @(Get-Label | Where-Object { $_.Disabled -eq $false })
Write-Host "  Found $($allLabels.Count) active label(s)." -ForegroundColor Gray

if ($allLabels.Count -eq 0) {
    Write-Warning '  No active sensitivity labels found. The script will continue but DLP rules will have no label conditions.'
    $selectedGuids = @()
} else {
    $lbl_v         = Show-LabelDialog -Labels $allLabels
    $selectedGuids = @($lbl_v.Keys)
    Write-Host "  Labels selected  : $($selectedGuids.Count)" -ForegroundColor Green
}
#endregion

# ============================================================
#region  COMMON SETTINGS
# ============================================================
$incidentContent = @(
    'Title',
    'Service',
    'MatchedItem',
    'RulesMatched',
    'Detections',
    'DocumentLastModifier',
    'SensitivityLabel',
    'Severity'
)

$alertMailbox = @($IncidentMailbox)

$tipEgress = 'Blocked: content bears a sensitivity label that restricts this egress path. Contact IT Security. | Blockiert: Vertraulichkeitsstufe schränkt diesen Übertragungsweg ein. IT-Sicherheit kontaktieren.'

#endregion

# ============================================================
#region  ENDPOINT DLP SITE GROUPS
# ============================================================
# Group display names are fixed — the tenant group import script always
# creates them with these exact names. GUIDs differ per tenant and are
# resolved at the start of the DEPLOYMENT region (after helper functions
# are defined and the IPPS session is active).
$cloudGroupNames   = @('Cloud Storage - Global', 'Cloud Storage - Regional & Hosting')
$webmailGroupNames = @('Webmail - Global & Privacy', 'Webmail - Regional')

# Generative AI Websites group uses a fixed well-known GUID (same in every tenant).
$aiGroupId = 'b88624dd-7364-49e7-aaad-ffe0247c572e'

$resolvedGroups        = @{}
$resolvedWebmailGroups = @{}
#endregion

# ============================================================
#region  HELPER FUNCTIONS
# ============================================================

function New-LabelConditionJson {
    # Builds AdvancedRule JSON for Exchange DLP policies (CT-EDLP-11).
    # Uses ContentIsNotLabeled=false ("content IS labeled, any label") as a broad condition.
    # AccessScope is added for CT-EDLP-11 to scope to external recipients only.
    param(
        [string[]]$Guids,
        [string]$Scope = ''
    )

    $subConditions = [System.Collections.Generic.List[object]]::new()
    $subConditions.Add([PSCustomObject]@{
        ConditionName = 'ContentIsNotLabeled'
        Value         = $false
    })

    if ($Scope -ne '') {
        # AccessScope expects a JSON primitive string, not an array
        $subConditions.Add([PSCustomObject]@{
            ConditionName = 'AccessScope'
            Value         = $Scope
        })
    }

    $root = [PSCustomObject]@{
        Version   = '1.0'
        Condition = [PSCustomObject]@{
            Operator      = 'And'
            SubConditions = $subConditions.ToArray()
        }
    }

    return ($root | ConvertTo-Json -Depth 10 -Compress)
}

function New-EndpointLabelConditionJson {
    # Builds AdvancedRule JSON for endpoint DLP rules.
    # Uses ContentContainsSensitiveInformation with PascalCase keys (Groups, Labels,
    # Name, Id, Operator, Type) and both Name+Id set to the GUID — the format the
    # Purview portal and endpoint DLP agent require to evaluate label conditions.
    param([string[]]$Guids)

    $labelEntries = @($Guids | ForEach-Object {
        [PSCustomObject]@{ Name = $_; Id = $_; Type = 'Sensitivity' }
    })

    $root = [PSCustomObject]@{
        Version   = '1.0'
        Condition = [PSCustomObject]@{
            Operator      = 'And'
            SubConditions = @(
                [PSCustomObject]@{
                    ConditionName = 'ContentContainsSensitiveInformation'
                    Value         = @(
                        [PSCustomObject]@{
                            Groups   = @(
                                [PSCustomObject]@{
                                    Name     = 'Default'
                                    Operator = 'Or'
                                    Labels   = $labelEntries
                                }
                            )
                            Operator = 'And'
                        }
                    )
                }
            )
        }
    }

    return ($root | ConvertTo-Json -Depth 50 -Compress)
}

function Get-SiteGroupMap {
    # Returns @{ 'Group Display Name' = 'guid' } from the tenant's PolicyConfig.
    $guidRx = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    $map = @{}
    $cfg = Get-PolicyConfig -ErrorAction SilentlyContinue
    if ($null -eq $cfg -or $null -eq $cfg.SiteGroupsPsws) { return $map }
    foreach ($g in @($cfg.SiteGroupsPsws)) {
        if ($null -eq $g) { continue }
        $entry = if ($g -is [string]) { $g | ConvertFrom-Json } else { $g }
        $name  = $entry.Name
        $id    = $entry.Id
        if (-not $id) {
            $id = $entry.PSObject.Properties.Value |
                  Where-Object { "$_" -match $guidRx } |
                  Select-Object -First 1
        }
        if ($name -and $id) { $map[$name] = "$id" }
    }
    return $map
}

function New-CloudEgressRestrictions {
    # Builds EndpointDlpRestrictions for CloudEgress and PasteToBrowser.
    # When $GroupMap contains entries for the requested $GroupNames, adds per-group
    # Block actions (cloudEgressGroup / pasteSensitiveDomainsGroup) in priority order,
    # matching the portal's "Sensitive service domain restrictions" configuration.
    # Falls back to plain Block entries when no groups are resolved.
    param(
        [hashtable]$GroupMap,
        [string[]]$GroupNames
    )

    $resolved = @($GroupNames | Where-Object { $GroupMap.ContainsKey($_) })

    if ($resolved.Count -eq 0) {
        return @(
            @{ setting = 'CloudEgress';    value = 'Block' }
            @{ setting = 'PasteToBrowser'; value = 'Block' }
        )
    }

    $grpEntries = @(for ($i = 0; $i -lt $resolved.Count; $i++) {
        @{ priority = "$($i + 1)"; id = $GroupMap[$resolved[$i]]; action = 'Block' }
    })

    return @(
        @{
            setting          = 'CloudEgress'
            value            = 'Block'
            defaultmessage   = 'none'
            cloudEgressGroup = $grpEntries
            appgroup         = 'none'
        }
        @{
            setting                    = 'PasteToBrowser'
            value                      = 'Block'
            defaultmessage             = 'none'
            pasteSensitiveDomainsGroup = $grpEntries
            appgroup                   = 'none'
        }
    )
}

function Initialize-DlpPolicy {
    param(
        [string]$Name,
        [string]$Mode,
        [string]$Comment,
        [hashtable]$ExtraParams = @{}
    )

    $cfg = $deployConfig[$Name]
    if ($null -eq $cfg -or -not $cfg.Enabled) {
        Write-Host "    [--] $Name skipped (not selected)." -ForegroundColor DarkGray
        return $null
    }

    $effectiveMode = $cfg.Mode

    $existing = Get-DlpCompliancePolicy -Identity $Name -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        if ($existing.Mode -ne $effectiveMode) {
            Write-Host "    [~~] $Name exists (Mode=$($existing.Mode)) — updating to $effectiveMode..." -ForegroundColor Yellow
            try {
                Set-DlpCompliancePolicy -Identity $Name -Mode $effectiveMode -Confirm:$false -ErrorAction Stop | Out-Null
                Write-Host "         Updated." -ForegroundColor Green
            } catch {
                Write-Warning "    [!]  Failed to update mode for $Name : $_"
            }
        } else {
            Write-Host "    [~~] $Name already exists (Mode=$($existing.Mode)). No changes needed." -ForegroundColor DarkGray
        }
        return $existing
    }

    $params = @{
        Name    = $Name
        Mode    = $effectiveMode
        Comment = $Comment
    }
    foreach ($k in $ExtraParams.Keys) { $params[$k] = $ExtraParams[$k] }

    Write-Host "    [+]  Creating policy: $Name (Mode=$effectiveMode)..." -ForegroundColor Gray

    $policy = New-DlpCompliancePolicy @params
    $script:createdPolicies.Add($Name)
    Write-Host "         Created." -ForegroundColor Green
    return $policy
}

function Initialize-DlpRule {
    param(
        [string]$Name,
        [string]$PolicyName,
        [string]$Comment = '',
        [hashtable]$RuleParams
    )

    $cfg = $deployConfig[$PolicyName]
    if ($null -eq $cfg -or -not $cfg.Enabled) {
        Write-Host "    [--] Rule $Name skipped (policy not enabled)." -ForegroundColor DarkGray
        return
    }

    $existing = Get-DlpComplianceRule -Identity $Name -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Write-Host "    [~~] Rule $Name exists — updating settings..." -ForegroundColor Yellow

        # Set-DlpComplianceRule silently ignores -AdvancedRule when other parameters are
        # present in the same call. Split into two calls: one for actions/notifications,
        # one for the condition JSON.
        $advancedRule = if ($RuleParams.ContainsKey('AdvancedRule')) { $RuleParams['AdvancedRule'] } else { $null }

        $setParams = @{ Identity = $Name }
        if ($Comment -ne '') { $setParams['Comment'] = $Comment }
        foreach ($k in $RuleParams.Keys) {
            if ($k -eq 'AdvancedRule') { continue }
            $setParams[$k] = $RuleParams[$k]
        }

        try {
            Set-DlpComplianceRule @setParams -Confirm:$false -ErrorAction Stop | Out-Null
            if ($null -ne $advancedRule) {
                Set-DlpComplianceRule -Identity $Name -AdvancedRule $advancedRule -Confirm:$false -ErrorAction Stop | Out-Null
            }
            Write-Host "         Updated." -ForegroundColor Green
        } catch {
            Write-Warning "    [!]  Failed to update rule $Name : $_"
            $script:pendingActions.Add("MANUAL: Update rule '$Name' under policy '$PolicyName'. Error: $_")
            $script:skippedRules.Add($Name)
        }
        return
    }

    $params = @{
        Name   = $Name
        Policy = $PolicyName
    }
    if ($Comment -ne '') { $params['Comment'] = $Comment }
    foreach ($k in $RuleParams.Keys) { $params[$k] = $RuleParams[$k] }

    Write-Host "    [+]  Creating rule : $Name..." -ForegroundColor Gray

    try {
        New-DlpComplianceRule @params -Confirm:$false -ErrorAction Stop | Out-Null
        $script:createdRules.Add($Name)
        Write-Host "         Created." -ForegroundColor Green
    } catch {
        Write-Warning "    [!]  Failed to create rule $Name : $_"
        $script:pendingActions.Add("MANUAL: Re-create rule '$Name' under policy '$PolicyName'. Error: $_")
        $script:skippedRules.Add($Name)
    }
}
#endregion

# ============================================================
#region  DEPLOYMENT
# ============================================================
Write-Section 'Deploying Policies'

# Resolve sensitive service domain group IDs for CT-EDLP-07, CT-EDLP-08, CT-EDLP-09.
# Groups are created by the tenant group import script; GUIDs differ per tenant.
# PolicyConfig is fetched once and shared across all three lookups.
Write-Host '  Resolving sensitive service domain group IDs...' -ForegroundColor Gray
$siteGroupMap = Get-SiteGroupMap
if ($siteGroupMap.Count -gt 0) {
    Write-Host "  PolicyConfig: $($siteGroupMap.Count) group(s) found:" -ForegroundColor Gray
    foreach ($gk in ($siteGroupMap.Keys | Sort-Object)) {
        Write-Host "    '$gk'  →  $($siteGroupMap[$gk])" -ForegroundColor DarkGray
    }
} else {
    Write-Warning '  No sensitive service domain groups found in PolicyConfig.'
}

foreach ($name in $cloudGroupNames) {
    if ($siteGroupMap.ContainsKey($name)) {
        $resolvedGroups[$name] = $siteGroupMap[$name]
        Write-Host "  [OK] $name → $($siteGroupMap[$name])" -ForegroundColor Green
    } else {
        Write-Warning "  [!] Group '$name' not found in PolicyConfig — CT-EDLP-08 will deploy without that group restriction."
    }
}
if ($resolvedGroups.Count -eq 0) {
    $script:pendingActions.Add("CONFIGURE Sensitive Service Domain Groups for CT-EDLP-08: groups ($($cloudGroupNames -join ', ')) were not found. Run the group import script first, then re-run this deployment.")
}

foreach ($name in $webmailGroupNames) {
    if ($siteGroupMap.ContainsKey($name)) {
        $resolvedWebmailGroups[$name] = $siteGroupMap[$name]
        Write-Host "  [OK] $name → $($siteGroupMap[$name])" -ForegroundColor Green
    } else {
        Write-Warning "  [!] Group '$name' not found in PolicyConfig — CT-EDLP-07 will deploy without that group restriction."
    }
}
if ($resolvedWebmailGroups.Count -eq 0) {
    $script:pendingActions.Add("CONFIGURE Sensitive Service Domain Groups for CT-EDLP-07: groups ($($webmailGroupNames -join ', ')) were not found. Run the group import script first, then re-run this deployment.")
}

Write-Host "  [OK] Generative AI Websites → $aiGroupId (fixed well-known ID)" -ForegroundColor Green
Write-Host ''

# ----------------------------------------------------------
#region CT-EDLP-01 — Removable Media
# ----------------------------------------------------------
$p01 = Initialize-DlpPolicy `
    -Name    'CT-EDLP-01-RemovableMedia' `
    -Mode    'TestWithoutNotifications' `
    -Comment 'CT-EDLP-01: Blocks copying of sensitivity-labelled files to removable media on managed endpoints.' `
    -ExtraParams @{ EndpointDlpLocation = 'All' }

if ($p01) {
    if ($selectedGuids.Count -gt 0) {
        Initialize-DlpRule `
            -Name       'CT-EDLP-01-RemovableMedia' `
            -PolicyName 'CT-EDLP-01-RemovableMedia' `
            -Comment    'Blocks removable media egress for sensitivity-labelled content.' `
            -RuleParams @{
                AdvancedRule                 = (New-EndpointLabelConditionJson -Guids $selectedGuids)
                NotifyUser                   = @('LastModifier')
                NotifyPolicyTipCustomText    = $tipEgress
                GenerateAlert                = $alertMailbox
                GenerateIncidentReport       = $alertMailbox
                IncidentReportContent        = $incidentContent
                ReportSeverityLevel          = 'High'
                Priority                     = 0
                EndpointDlpRestrictions      = @(@{ setting = 'RemovableMedia'; value = 'Block' })
            }
    } else {
        Write-Warning '    No labels selected — CT-EDLP-01 rule skipped.'
        $script:pendingActions.Add('Re-run after selecting labels to deploy CT-EDLP-01.')
    }
}
#endregion

# ----------------------------------------------------------
#region CT-EDLP-02 — Print
# ----------------------------------------------------------
$p02 = Initialize-DlpPolicy `
    -Name    'CT-EDLP-02-Print' `
    -Mode    'TestWithoutNotifications' `
    -Comment 'CT-EDLP-02: Blocks printing of sensitivity-labelled documents on managed endpoints.' `
    -ExtraParams @{ EndpointDlpLocation = 'All' }

if ($p02) {
    if ($selectedGuids.Count -gt 0) {
        Initialize-DlpRule `
            -Name       'CT-EDLP-02-Print' `
            -PolicyName 'CT-EDLP-02-Print' `
            -Comment    'Blocks print egress for sensitivity-labelled content.' `
            -RuleParams @{
                AdvancedRule                 = (New-EndpointLabelConditionJson -Guids $selectedGuids)
                NotifyUser                   = @('LastModifier')
                NotifyPolicyTipCustomText    = $tipEgress
                GenerateAlert                = $alertMailbox
                GenerateIncidentReport       = $alertMailbox
                IncidentReportContent        = $incidentContent
                ReportSeverityLevel          = 'High'
                Priority                     = 0
                EndpointDlpRestrictions      = @(@{ setting = 'Print'; value = 'Block' })
            }
    } else {
        Write-Warning '    No labels selected — CT-EDLP-02 rule skipped.'
        $script:pendingActions.Add('Re-run after selecting labels to deploy CT-EDLP-02.')
    }
}
#endregion

# ----------------------------------------------------------
#region CT-EDLP-03 — Clipboard Copy
# ----------------------------------------------------------
$p03 = Initialize-DlpPolicy `
    -Name    'CT-EDLP-03-Clipboard' `
    -Mode    'TestWithoutNotifications' `
    -Comment 'CT-EDLP-03: Blocks clipboard copy of sensitivity-labelled content on managed endpoints.' `
    -ExtraParams @{ EndpointDlpLocation = 'All' }

if ($p03) {
    if ($selectedGuids.Count -gt 0) {
        Initialize-DlpRule `
            -Name       'CT-EDLP-03-Clipboard' `
            -PolicyName 'CT-EDLP-03-Clipboard' `
            -Comment    'Blocks clipboard copy egress for sensitivity-labelled content.' `
            -RuleParams @{
                AdvancedRule                 = (New-EndpointLabelConditionJson -Guids $selectedGuids)
                NotifyUser                   = @('LastModifier')
                NotifyPolicyTipCustomText    = $tipEgress
                GenerateAlert                = $alertMailbox
                GenerateIncidentReport       = $alertMailbox
                IncidentReportContent        = $incidentContent
                ReportSeverityLevel          = 'High'
                Priority                     = 0
                EndpointDlpRestrictions      = @(@{ setting = 'CopyPaste'; value = 'Block' })
            }
    } else {
        Write-Warning '    No labels selected — CT-EDLP-03 rule skipped.'
        $script:pendingActions.Add('Re-run after selecting labels to deploy CT-EDLP-03.')
    }
}
#endregion

# ----------------------------------------------------------
#region CT-EDLP-04 — Bluetooth Transfer
# ----------------------------------------------------------
$p04 = Initialize-DlpPolicy `
    -Name    'CT-EDLP-04-Bluetooth' `
    -Mode    'TestWithoutNotifications' `
    -Comment 'CT-EDLP-04: Blocks Bluetooth transfer of sensitivity-labelled files on managed endpoints.' `
    -ExtraParams @{ EndpointDlpLocation = 'All' }

if ($p04) {
    if ($selectedGuids.Count -gt 0) {
        Initialize-DlpRule `
            -Name       'CT-EDLP-04-Bluetooth' `
            -PolicyName 'CT-EDLP-04-Bluetooth' `
            -Comment    'Blocks Bluetooth egress for sensitivity-labelled content.' `
            -RuleParams @{
                AdvancedRule                 = (New-EndpointLabelConditionJson -Guids $selectedGuids)
                NotifyUser                   = @('LastModifier')
                NotifyPolicyTipCustomText    = $tipEgress
                GenerateAlert                = $alertMailbox
                GenerateIncidentReport       = $alertMailbox
                IncidentReportContent        = $incidentContent
                ReportSeverityLevel          = 'High'
                Priority                     = 0
                EndpointDlpRestrictions      = @(@{ setting = 'UnallowedBluetoothTransferApps'; value = 'Block' })
            }
    } else {
        Write-Warning '    No labels selected — CT-EDLP-04 rule skipped.'
        $script:pendingActions.Add('Re-run after selecting labels to deploy CT-EDLP-04.')
    }
}
#endregion

# ----------------------------------------------------------
#region CT-EDLP-05 — RDP Copy
# ----------------------------------------------------------
$p05 = Initialize-DlpPolicy `
    -Name    'CT-EDLP-05-RDPCopy' `
    -Mode    'TestWithoutNotifications' `
    -Comment 'CT-EDLP-05: Blocks clipboard/drive redirection of sensitivity-labelled content during RDP sessions.' `
    -ExtraParams @{ EndpointDlpLocation = 'All' }

if ($p05) {
    if ($selectedGuids.Count -gt 0) {
        Initialize-DlpRule `
            -Name       'CT-EDLP-05-RDPCopy' `
            -PolicyName 'CT-EDLP-05-RDPCopy' `
            -Comment    'Blocks RDP copy egress for sensitivity-labelled content.' `
            -RuleParams @{
                AdvancedRule                 = (New-EndpointLabelConditionJson -Guids $selectedGuids)
                NotifyUser                   = @('LastModifier')
                NotifyPolicyTipCustomText    = $tipEgress
                GenerateAlert                = $alertMailbox
                GenerateIncidentReport       = $alertMailbox
                IncidentReportContent        = $incidentContent
                ReportSeverityLevel          = 'High'
                Priority                     = 0
                EndpointDlpRestrictions      = @(@{ setting = 'RemoteDesktopServices'; value = 'Block' })
            }
    } else {
        Write-Warning '    No labels selected — CT-EDLP-05 rule skipped.'
        $script:pendingActions.Add('Re-run after selecting labels to deploy CT-EDLP-05.')
    }
}
#endregion

# ----------------------------------------------------------
#region CT-EDLP-06 — Network Share Copy
# ----------------------------------------------------------
$p06 = Initialize-DlpPolicy `
    -Name    'CT-EDLP-06-NetworkShare' `
    -Mode    'TestWithoutNotifications' `
    -Comment 'CT-EDLP-06: Blocks copying of sensitivity-labelled files to network shares (SMB).' `
    -ExtraParams @{ EndpointDlpLocation = 'All' }

if ($p06) {
    if ($selectedGuids.Count -gt 0) {
        Initialize-DlpRule `
            -Name       'CT-EDLP-06-NetworkShare' `
            -PolicyName 'CT-EDLP-06-NetworkShare' `
            -Comment    'Blocks network share egress for sensitivity-labelled content.' `
            -RuleParams @{
                AdvancedRule                 = (New-EndpointLabelConditionJson -Guids $selectedGuids)
                NotifyUser                   = @('LastModifier')
                NotifyPolicyTipCustomText    = $tipEgress
                GenerateAlert                = $alertMailbox
                GenerateIncidentReport       = $alertMailbox
                IncidentReportContent        = $incidentContent
                ReportSeverityLevel          = 'High'
                Priority                     = 0
                EndpointDlpRestrictions      = @(@{ setting = 'NetworkShare'; value = 'Block' })
            }
    } else {
        Write-Warning '    No labels selected — CT-EDLP-06 rule skipped.'
        $script:pendingActions.Add('Re-run after selecting labels to deploy CT-EDLP-06.')
    }
}
#endregion

# ----------------------------------------------------------
#region CT-EDLP-07 — Webmail Upload
# ----------------------------------------------------------
$p07 = Initialize-DlpPolicy `
    -Name    'CT-EDLP-07-WebmailUpload' `
    -Mode    'TestWithoutNotifications' `
    -Comment 'CT-EDLP-07: Blocks browser upload of sensitivity-labelled files to personal webmail services.' `
    -ExtraParams @{ EndpointDlpLocation = 'All' }

if ($p07) {
    if ($selectedGuids.Count -gt 0) {
        Initialize-DlpRule `
            -Name       'CT-EDLP-07-WebmailUpload' `
            -PolicyName 'CT-EDLP-07-WebmailUpload' `
            -Comment    'Blocks browser upload egress for sensitivity-labelled content to webmail services.' `
            -RuleParams @{
                AdvancedRule                 = (New-EndpointLabelConditionJson -Guids $selectedGuids)
                NotifyUser                   = @('LastModifier')
                NotifyPolicyTipCustomText    = $tipEgress
                GenerateAlert                = $alertMailbox
                GenerateIncidentReport       = $alertMailbox
                IncidentReportContent        = $incidentContent
                ReportSeverityLevel          = 'High'
                Priority                     = 0
                EndpointDlpRestrictions      = (New-CloudEgressRestrictions -GroupMap $resolvedWebmailGroups -GroupNames $webmailGroupNames)
            }
    } else {
        Write-Warning '    No labels selected — CT-EDLP-07 rule skipped.'
        $script:pendingActions.Add('Re-run after selecting labels to deploy CT-EDLP-07.')
    }
    $script:pendingActions.Add('CONFIGURE Cloud Service Domains: classify personal webmail providers (Gmail, Outlook.com, Yahoo Mail) in Endpoint DLP → Cloud Service Domains before enforcing CT-EDLP-07.')
}
#endregion

# ----------------------------------------------------------
#region CT-EDLP-08 — Cloud Storage Upload
# ----------------------------------------------------------
$p08 = Initialize-DlpPolicy `
    -Name    'CT-EDLP-08-CloudStorage' `
    -Mode    'TestWithoutNotifications' `
    -Comment 'CT-EDLP-08: Blocks upload of sensitivity-labelled files to unsanctioned cloud storage services.' `
    -ExtraParams @{ EndpointDlpLocation = 'All' }

if ($p08) {
    if ($selectedGuids.Count -gt 0) {
        Initialize-DlpRule `
            -Name       'CT-EDLP-08-CloudStorage' `
            -PolicyName 'CT-EDLP-08-CloudStorage' `
            -Comment    'Blocks cloud storage upload egress for sensitivity-labelled content.' `
            -RuleParams @{
                AdvancedRule                 = (New-EndpointLabelConditionJson -Guids $selectedGuids)
                NotifyUser                   = @('LastModifier')
                NotifyPolicyTipCustomText    = $tipEgress
                GenerateAlert                = $alertMailbox
                GenerateIncidentReport       = $alertMailbox
                IncidentReportContent        = $incidentContent
                ReportSeverityLevel          = 'High'
                Priority                     = 0
                EndpointDlpRestrictions      = (New-CloudEgressRestrictions -GroupMap $resolvedGroups -GroupNames $cloudGroupNames)
            }
    } else {
        Write-Warning '    No labels selected — CT-EDLP-08 rule skipped.'
        $script:pendingActions.Add('Re-run after selecting labels to deploy CT-EDLP-08.')
    }
    $script:pendingActions.Add('NOTE CT-EDLP-08: Paste-to-browser blocking does not trigger on label-matched content (the endpoint DLP paste control evaluates pasted text independently of the source file label). To block paste to cloud storage sites, create a separate rule that matches sensitive information types (SITs).')
}
#endregion

# ----------------------------------------------------------
#region CT-EDLP-09 — Generative AI Websites
# ----------------------------------------------------------
$p09 = Initialize-DlpPolicy `
    -Name    'CT-EDLP-09-GenerativeAI' `
    -Mode    'TestWithoutNotifications' `
    -Comment 'CT-EDLP-09: Blocks pasting or uploading sensitivity-labelled content to generative AI websites.' `
    -ExtraParams @{ EndpointDlpLocation = 'All' }

if ($p09) {
    if ($selectedGuids.Count -gt 0) {
        Initialize-DlpRule `
            -Name       'CT-EDLP-09-GenerativeAI' `
            -PolicyName 'CT-EDLP-09-GenerativeAI' `
            -Comment    'Blocks generative AI website egress for sensitivity-labelled content.' `
            -RuleParams @{
                AdvancedRule                 = (New-EndpointLabelConditionJson -Guids $selectedGuids)
                NotifyUser                   = @('LastModifier')
                NotifyPolicyTipCustomText    = $tipEgress
                GenerateAlert                = $alertMailbox
                GenerateIncidentReport       = $alertMailbox
                IncidentReportContent        = $incidentContent
                ReportSeverityLevel          = 'High'
                Priority                     = 0
                EndpointDlpRestrictions      = @(
                                                   @{ setting = 'AccessByAIAgent'; defaultmessage = 'none'; appgroup = 'none'; value = 'Block' }
                                                   @{ setting = 'CloudEgress';     defaultmessage = 'none'; appgroup = 'none'; value = 'Block'; cloudEgressGroup          = @(@{ id = $aiGroupId; action = 'Block'; priority = '1' }) }
                                                   @{ setting = 'PasteToBrowser';  defaultmessage = 'none'; appgroup = 'none'; value = 'Block'; pasteSensitiveDomainsGroup = @(@{ id = $aiGroupId; action = 'Block'; priority = '1' }) }
                                               )
            }
    } else {
        Write-Warning '    No labels selected — CT-EDLP-09 rule skipped.'
        $script:pendingActions.Add('Re-run after selecting labels to deploy CT-EDLP-09.')
    }
    $script:pendingActions.Add("VERIFY CT-EDLP-09: 'GenerativeAIWebsites' restriction requires Microsoft Purview AI Hub feature + DLP for AI Apps license. If rule creation failed, classify AI site domains under Cloud Service Domains manually.")
}
#endregion

# ----------------------------------------------------------
#region CT-EDLP-10 — Unallowed Applications
# ----------------------------------------------------------
$p10 = Initialize-DlpPolicy `
    -Name    'CT-EDLP-10-UnallowedApps' `
    -Mode    'TestWithoutNotifications' `
    -Comment 'CT-EDLP-10: Blocks access to sensitivity-labelled files by applications in Restricted App Groups.' `
    -ExtraParams @{ EndpointDlpLocation = 'All' }

if ($p10) {
    if ($selectedGuids.Count -gt 0) {
        Initialize-DlpRule `
            -Name       'CT-EDLP-10-UnallowedApps' `
            -PolicyName 'CT-EDLP-10-UnallowedApps' `
            -Comment    'Blocks unallowed application access to sensitivity-labelled content.' `
            -RuleParams @{
                AdvancedRule                 = (New-EndpointLabelConditionJson -Guids $selectedGuids)
                NotifyUser                   = @('LastModifier')
                NotifyPolicyTipCustomText    = $tipEgress
                GenerateAlert                = $alertMailbox
                GenerateIncidentReport       = $alertMailbox
                IncidentReportContent        = $incidentContent
                ReportSeverityLevel          = 'High'
                Priority                     = 0
                EndpointDlpRestrictions      = @(@{ setting = 'UnallowedApps'; value = 'Block' })
            }
    } else {
        Write-Warning '    No labels selected — CT-EDLP-10 rule skipped.'
        $script:pendingActions.Add('Re-run after selecting labels to deploy CT-EDLP-10.')
    }
    $script:pendingActions.Add('CONFIGURE Restricted App Groups in Endpoint DLP settings (Purview portal → Settings → Endpoint DLP settings → Restricted apps and app groups) before CT-EDLP-10 is effective.')
}
#endregion


# ----------------------------------------------------------
#region CT-EDLP-11 — Exchange Email (External)
# ----------------------------------------------------------
$p11 = Initialize-DlpPolicy `
    -Name    'CT-EDLP-11-Exchange' `
    -Mode    'TestWithoutNotifications' `
    -Comment 'CT-EDLP-11: Blocks sending of sensitivity-labelled content via Exchange email to external recipients.' `
    -ExtraParams @{ ExchangeLocation = 'All' }

if ($p11) {
    if ($selectedGuids.Count -gt 0) {
        Initialize-DlpRule `
            -Name       'CT-EDLP-11-Exchange' `
            -PolicyName 'CT-EDLP-11-Exchange' `
            -Comment    'Blocks external Exchange email egress for sensitivity-labelled content.' `
            -RuleParams @{
                AdvancedRule                 = (New-LabelConditionJson -Guids $selectedGuids -Scope 'NotInOrganization')
                BlockAccess                  = $true
                BlockAccessScope             = 'All'
                NotifyUser                   = @('LastModifier')
                NotifyPolicyTipCustomText    = $tipEgress
                GenerateAlert                = $alertMailbox
                GenerateIncidentReport       = $alertMailbox
                IncidentReportContent        = $incidentContent
                ReportSeverityLevel          = 'High'
                Priority                     = 0
            }
    } else {
        Write-Warning '    No labels selected — CT-EDLP-11 rule skipped.'
        $script:pendingActions.Add('Re-run after selecting labels to deploy CT-EDLP-11.')
    }
}
#endregion

#endregion  # DEPLOYMENT

# ============================================================
#region  SUMMARY
# ============================================================
Write-Section 'Deployment Summary'

$allPolicyNames = @(
    'CT-EDLP-01-RemovableMedia',
    'CT-EDLP-02-Print',
    'CT-EDLP-03-Clipboard',
    'CT-EDLP-04-Bluetooth',
    'CT-EDLP-05-RDPCopy',
    'CT-EDLP-06-NetworkShare',
    'CT-EDLP-07-WebmailUpload',
    'CT-EDLP-08-CloudStorage',
    'CT-EDLP-09-GenerativeAI',
    'CT-EDLP-10-UnallowedApps',
    'CT-EDLP-11-Exchange'
)

Write-Host '  Policy Status:' -ForegroundColor Cyan
Write-Host ''

foreach ($pName in $allPolicyNames) {
    $pol = Get-DlpCompliancePolicy -Identity $pName -ErrorAction SilentlyContinue
    if ($null -eq $pol) {
        Write-Host ("  [--]  {0,-38}  not deployed" -f $pName) -ForegroundColor DarkGray
    } else {
        $rules     = @(Get-DlpComplianceRule -Policy $pName -ErrorAction SilentlyContinue)
        $ruleCount = $rules.Count
        $modeStr   = $pol.Mode
        $modeColor = switch ($modeStr) {
            'TestWithoutNotifications' { 'Yellow' }
            'TestWithNotifications'    { 'Yellow' }
            'Enable'                   { 'Green'  }
            default                    { 'Gray'   }
        }
        if ($ruleCount -gt 0) {
            Write-Host ("  [OK]  {0,-38}  Mode={1}  Rules={2}" -f $pName, $modeStr, $ruleCount) -ForegroundColor $modeColor
        } else {
            Write-Host ("  [!]   {0,-38}  Mode={1}  Rules={2} (no rules!)" -f $pName, $modeStr, $ruleCount) -ForegroundColor Red
        }
    }
}

Write-Host ''

if ($script:skippedRules.Count -gt 0) {
    Write-Host '  Skipped / Failed Rules:' -ForegroundColor Red
    foreach ($sr in $script:skippedRules) {
        Write-Host "    - $sr" -ForegroundColor Red
    }
    Write-Host ''
}

if ($script:pendingActions.Count -gt 0) {
    Write-Host '  Pending Actions Required:' -ForegroundColor Yellow
    $i = 1
    foreach ($pa in $script:pendingActions) {
        Write-Host "    $i. $pa" -ForegroundColor Yellow
        $i++
    }
    Write-Host ''
}

Write-Host '  Recommended Next Steps:' -ForegroundColor Cyan
Write-Host ''
Write-Host '    1. Review Activity Explorer for 2+ weeks before switching any policy' -ForegroundColor White
Write-Host '       to Enable mode.' -ForegroundColor White
Write-Host '    2. Start with CT-EDLP-11 (Exchange) as the lowest-risk enforce candidate.' -ForegroundColor White
Write-Host '    3. Address all Pending Actions above before enforcing browser/cloud policies.' -ForegroundColor White
Write-Host '    4. Validate label coverage in Activity Explorer — confirm expected labels' -ForegroundColor White
Write-Host '       appear in match events.' -ForegroundColor White
Write-Host "    5. Review incident mailbox ($IncidentMailbox) regularly during the simulation period." -ForegroundColor White
Write-Host ''
Write-Host ('=' * 60) -ForegroundColor Cyan
Write-Host '  CT-EDLP deployment complete.' -ForegroundColor Green
Write-Host ('=' * 60) -ForegroundColor Cyan
Write-Host ''
#endregion
