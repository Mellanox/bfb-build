#!/bin/bash

# Common functions for BFB build scripts

#
# Function: download_files_by_pattern
# Description: Downloads files from a URL that match a specific pattern
# Parameters:
#   $1 - base_url: The URL to fetch the listing from
#   $2 - pattern: The regex pattern to match files against
#   $3 - target_dir (optional): Target directory for downloads (default: current directory)
# Returns: 0 on success, 1 on error
#
download_files_by_pattern() {
    local base_url="$1"
    local pattern="$2"
    local target_dir="${3:-.}"
    local listing_file="listing.html"
    
    # Validate required parameters
    if [[ -z "$base_url" || -z "$pattern" ]]; then
        echo "Error: download_files_by_pattern requires base_url and pattern parameters" >&2
        echo "Usage: download_files_by_pattern <base_url> <pattern> [target_dir]" >&2
        return 1
    fi
    
    # Create target directory if it doesn't exist
    if [[ "$target_dir" != "." ]]; then
        mkdir -p "$target_dir"
    fi
    
    echo "Downloading files matching pattern '$pattern' from $base_url..."
    
    # Download the directory listing
    if ! wget -q -O "$listing_file" "$base_url/"; then
        echo "Error: Failed to download listing from $base_url" >&2
        return 1
    fi
    
    # Extract filenames that match the pattern and download them
    local download_count=0
    while IFS= read -r filename; do
        if [[ -n "$filename" ]]; then
            echo "Downloading: $filename"
            if wget -q -P "$target_dir" "${base_url}/${filename}"; then
                ((download_count++))
            else
                echo "Warning: Failed to download $filename" >&2
            fi
        fi
    done < <(grep -oP '(?<=href=")[^"]*' "$listing_file" | grep -E "$pattern")
    
    # Clean up listing file
    rm -f "$listing_file"
    
    echo "Downloaded $download_count file(s) matching pattern '$pattern'"
    return 0
}
