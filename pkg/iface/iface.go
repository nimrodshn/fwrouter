package iface

import (
	"fmt"
	"log"
	"net"

	"github.com/vishvananda/netlink"
)

// VerifyExists verifies if an interface named 'ifaceName' exists.
func VerifyExists(ifaceName string) (netlink.Link, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	ifaceMissing := true
	for _, iface := range interfaces {
		if iface.Name == ifaceName {
			ifaceMissing = false
		}
	}

	// Create the egress interface if its missing.
	var res netlink.Link
	if ifaceMissing {
		la := netlink.NewLinkAttrs()
		la.Name = ifaceName
		res = &netlink.Dummy{
			LinkAttrs: la,
		}
		err := netlink.LinkAdd(res)
		if err != nil {
			log.Printf("could not add link %s: %v\n", la.Name, err)
			return nil, err
		}
		err = netlink.LinkSetUp(res)
		if err != nil {
			log.Printf("could not activate link %s: %v\n", la.Name, err)
			return nil, err
		}
	} else {
		res, err = netlink.LinkByName(ifaceName)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

// DetacheIface detaches the interface associated with iface.
func DetachIface(iface netlink.Link) error {
	return netlink.LinkDel(iface)
}

func GetIPAddress(iface netlink.Link) (net.IP, error) {
	defIface, err := net.InterfaceByIndex(iface.Attrs().Index)
	if err != nil {
		return nil, err
	}
	addrs, err := defIface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP, nil
			}
		}
	}
	return nil, fmt.Errorf("failed to find address attached to interface '%s'",
		iface.Attrs().Name)
}
