# Network Topology Page — Detailed UI/UX Design Specification (AI Generation Guide)

---

# Overview

The Network Topology page is the operational command center of the Circle Mesh network.

Unlike a traditional network diagram, this page visualizes the live state of an organization's distributed mesh infrastructure on top of a real-world geographic map. Every node displayed represents a real device, relay, lighthouse, or trusted endpoint received from backend APIs.

The design should feel like a modern Security Operations Center (SOC), Mission Control dashboard, or military command interface.

The interface must prioritize:

- Situational awareness
- Live operational status
- Geographic understanding
- Trust relationships
- Mesh routing visibility
- Geofence awareness
- Backend health
- Immediate readability

The page should never look like a colorful infographic.

It should look professional, dense, minimal, and operational.

---

# Overall Theme

The visual style should resemble:

- Enterprise SOC dashboards
- Satellite command systems
- Dark cyber intelligence interfaces
- Kubernetes observability dashboards
- Cloudflare Radar
- Azure Network Watcher
- Cisco ThousandEyes
- Datadog Network Maps

Avoid:

- Gaming UI
- Neon cyberpunk
- Purple themes
- Cartoon styling
- Excessive gradients
- Large glowing elements

Everything should communicate precision.

---

# Color Palette

Background

Deep charcoal

#070707

Panels

#151617

Secondary Panels

#1B1D1F

Borders

rgba(255,255,255,0.08)

Grid Lines

rgba(255,255,255,0.04)

Primary Accent

#20C7D9

Secondary Accent

#18B5C8

Healthy

#3AC569

Warning

#F4B640

Offline

#7A7A7A

Critical

#E14D4D

Text Primary

#F2F2F2

Text Secondary

#B3B3B3

Muted

#7A7A7A

Map Labels

Light gray

No purple colors anywhere.

---

# Layout Structure

The page consists of five primary regions.

```
-------------------------------------------------------------
 Top Navigation
-------------------------------------------------------------
 Left Sidebar |            Interactive Map            | Right
              |                                       | Panel
              |                                       |
              |                                       |
              |                                       |
-------------------------------------------------------------
 Bottom Status Bar
-------------------------------------------------------------
```

The map occupies roughly 70–75% of the page width.

The side panel occupies approximately 25–30%.

The map is always the visual focus.

---

# Header

The top header should remain compact.

Contents:

- Network Topology title
- Environment badge
- Live/Fallback badge
- Last synchronization timestamp
- Refresh button
- Search box
- Filter button

Example

```
Network Topology

Environment: Production

Status: LIVE

Updated:
13:04:51 UTC

Refresh
```

The LIVE badge should glow subtly.

Fallback mode should display amber.

---

# Live Status Indicator

Top right corner.

Small pill badge.

States:

Live

Color:

Green

Text:

LIVE

Meaning:

Backend currently supplying real topology.

---

Fallback

Amber

Text:

FIXTURE

Meaning:

Rendering fallback topology.

---

Loading

Blue spinner

Text:

SYNCING

---

Offline

Gray

Text:

DISCONNECTED

---

# Main Map

The centerpiece.

Uses:

Dark CARTO tiles

OpenStreetMap data

No Google Maps dependency.

Projection:

Web Mercator

The map should resemble:

Cloudflare Radar

Dark Earth

Azure Maps Dark

Map characteristics:

Minimal roads

Minimal labels

Dark oceans

Dark landmass

Thin borders

No unnecessary saturation

---

# Zoom

Supported zoom:

1–16

Behavior

Far Zoom

Small node dots

Hidden labels

Only major mesh visible

---

Medium Zoom

Node labels appear

Role icons appear

Mesh routes visible

---

Near Zoom

Node information expands

Overlay IP shown

Attestation badges visible

Relay details visible

Connection animations become easier to inspect

---

Marker Scaling

Markers should counter-scale.

As zoom increases:

Icons stay approximately the same visual size.

Countries should never become hidden behind icons.

---

# Nodes

Every backend peer becomes one node.

Nodes should look clean.

Circular.

Flat.

Professional.

---

Node Size

Far zoom

6 px

Medium

10 px

Near

14 px

Hover

18 px

---

Node Roles

Each node displays a role icon.

Primary Lighthouse

Compass icon

Largest

Highest priority

---

Lighthouse

Beacon icon

---

Relay

Bidirectional arrows

---

Member

Simple circle

---

Unknown

Question icon

---

# Node Status

Online

Green

---

Stale

Amber

---

Offline

Gray

---

Unknown

Dark gray

---

# Trust State

Trusted

Thin cyan outer ring

---

Attested

Double cyan ring

Tiny shield icon

---

Untrusted

Red outline

---

Pending

Amber dashed outline

---

# Hover Card

Hovering any node opens an information card.

Contains:

Hostname

Peer ID

Overlay IP

Public IP

Node role

Online state

Trust state

Last seen

Version

Operating system

Connected peers

Relay

Mesh latency

Geofence state

Attestation

Example

```
Lighthouse-01

Role:
Primary Lighthouse

Overlay:
100.64.10.2

Public:
34.83.x.x

Trust:
Attested

Status:
Healthy

Latency:
11 ms

Peers:
46

Version:
2.1.0
```

---

# Selected Node

Clicking a node:

Highlights it

Centers map

Expands right-side detail panel

All connected edges become emphasized.

Other nodes dim slightly.

---

# Links

Three different connection types.

---

Mesh Link

Solid cyan line

Animated packets

Represents normal peer communication.

---

Relay Link

Dashed teal line

Thicker

Arrow direction

Represents relay routing.

---

Attestation Link

White thin line

Shield pulse animation

Represents verified trust relationship.

---

Link Animations

Tiny packet dots travel continuously.

Animation speed reflects connection quality.

Fast

Healthy

Slow

High latency

Stopped

Offline

---

# Node Clustering

When zoomed far out:

Nearby nodes cluster.

Cluster displays

```
18
```

instead of many nodes.

Expands automatically while zooming.

---

# Search

Search box should instantly locate:

Hostname

Peer ID

Overlay IP

Public IP

Relay

Lighthouse

Selecting result:

Centers map

Highlights node

---

# Filters

Operator should filter by:

Role

Status

Trust

Relay

Lighthouse

Online

Offline

Untrusted

Attested

Geofence

Mesh segment

Organization

Site

---

# Right Sidebar

This is the operational intelligence panel.

Contains multiple collapsible cards.

---

## Network Summary

Displays:

Total Nodes

Online

Offline

Relays

Lighthouses

Members

Attested

Untrusted

Mesh Links

Average Latency

Example

```
Nodes
148

Online
132

Offline
16

Relays
9

Lighthouses
2

Mesh Links
514
```

---

## Selected Node Details

Shows complete backend information.

Actions

View Peer

Copy Overlay IP

Ping

Trace

Inspect

---

## Trust Overview

Pie chart

Attested

Pending

Failed

Unknown

---

## Relay Health

Displays

Relay load

Traffic

Connected peers

CPU

Heartbeat

---

## Lighthouse Status

Displays

Primary

Secondary

Election state

Discovery health

Connected members

---

## Mesh Health

Displays

Average latency

Packet loss

Disconnected peers

Reconnections

Topology age

---

# Geofence Section

One of the most important sections.

Contains:

Current location

Source

Backend state

Zone count

Current zone

Automation enabled

RF capture

Latest event

Alert count

---

# Geofence Visualization

Zones appear as translucent circles.

Fill

Very subtle cyan

Border

Dashed cyan

Selected zone

Solid border

Slight glow

---

Zone States

Inside

Green outline

Outside

Gray

Violation

Red pulse

Pending

Amber

---

# Zone Card

Displays

Zone Name

Radius

Automation

RF Enabled

Created

Updated

Actions

Edit

Delete

Capture RF

Test

---

# Geofence Toolbar

Buttons

Report Location

Create Zone

Toggle Automation

Capture RF

Refresh

Test Actions

---

# Bottom Status Bar

Persistent.

Displays:

Backend connection

WebSocket

Peer count

Relay count

Topology version

Current zoom

Cursor coordinates

Example

```
Backend Connected

Peers 146

Relays 8

Zoom 7

WebSocket Healthy

Topology v2.1
```

---

# Animations

Animations should be subtle.

Allowed

Packet movement

Node pulse

Trust pulse

Selection glow

Panel fade

Loading spinner

Not allowed

Bouncing

Flashing

Heavy glows

Random movement

Particle explosions

---

# Empty State

If backend returns no peers:

Display:

"No live topology available."

Below:

Rendering fallback demonstration topology.

Map remains interactive.

Fallback badge becomes visible.

---

# Loading State

Map loads first.

Then

Nodes

Then

Links

Then

Geofence

Then

Sidebar metrics

Skeleton placeholders appear while loading.

---

# Responsiveness

Desktop

Primary experience.

Tablet

Sidebar collapses into drawer.

Mobile

Map fills screen.

Sidebar becomes bottom sheet.

---

# Accessibility

High contrast text

Keyboard navigation

Screen reader labels

Color-independent status indicators

Minimum 4.5:1 contrast

---

# Performance

Support:

500+ nodes

2000+ edges

Smooth pan

Smooth zoom

60 FPS target

Efficient clustering

Virtual rendering

Lazy loading

Canvas/WebGL rendering preferred over SVG for large datasets.

---

# Design Principles

The interface should communicate:

- Operational awareness over aesthetics.
- Geographic context over abstract diagrams.
- Trust relationships over decorative visuals.
- Real-time infrastructure health over static reporting.
- Dense but readable information.
- Minimal color usage with meaningful status indicators.
- Smooth interaction without distracting animations.
- Enterprise-grade professionalism suitable for SOC analysts and network operators.