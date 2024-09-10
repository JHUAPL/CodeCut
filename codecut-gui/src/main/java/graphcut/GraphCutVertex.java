/* ###
 * © 2021 The Johns Hopkins University Applied Physics Laboratory LLC (JHU/APL).  
 * All Rights Reserved.
 * 
 * This material may be only be used, modified, or reproduced by or for the U.S. 
 * Government pursuant to the license rights granted under the clauses at 
 * DFARS 252.227-7013/7014 or FAR 52.227-14. For any other permission, please 
 * contact the Office of Technology Transfer at JHU/APL.
 * 
 * NO WARRANTY, NO LIABILITY. THIS MATERIAL IS PROVIDED “AS IS.” JHU/APL MAKES 
 * NO REPRESENTATION OR WARRANTY WITH RESPECT TO THE PERFORMANCE OF THE MATERIALS, 
 * INCLUDING THEIR SAFETY, EFFECTIVENESS, OR COMMERCIAL VIABILITY, AND DISCLAIMS 
 * ALL WARRANTIES IN THE MATERIAL, WHETHER EXPRESS OR IMPLIED, INCLUDING 
 * (BUT NOT LIMITED TO) ANY AND ALL IMPLIED WARRANTIES OF PERFORMANCE, 
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT OF 
 * INTELLECTUAL PROPERTY OR OTHER THIRD PARTY RIGHTS. ANY USER OF THE MATERIAL 
 * ASSUMES THE ENTIRE RISK AND LIABILITY FOR USING THE MATERIAL. IN NO EVENT SHALL 
 * JHU/APL BE LIABLE TO ANY USER OF THE MATERIAL FOR ANY ACTUAL, INDIRECT, 
 * CONSEQUENTIAL, SPECIAL OR OTHER DAMAGES ARISING FROM THE USE OF, OR INABILITY TO 
 * USE, THE MATERIAL, INCLUDING, BUT NOT LIMITED TO, ANY DAMAGES FOR LOST PROFITS. 
 *
 * HAVE A NICE DAY.
 */

/* This material is based upon work supported by the Defense Advanced Research
 * Projects Agency (DARPA) and Naval Information Warfare Center Pacific (NIWC Pacific)
 * under Contract Number N66001-20-C-4024.
*/

/*
 * Heavily Borrowed from Ghidra file /Features Graph FunctionCalls/src/main/java/functioncalls/graph/FcgVertex.java
 */


package graphcut;

import java.awt.*;
import java.awt.geom.Area;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Ellipse2D.Double;
import java.awt.image.BufferedImage;
import java.util.Objects;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;

import ghidra.program.model.symbol.Namespace;

import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GDLabel;
import functioncalls.graph.FcgDirection;
import functioncalls.graph.FcgVertex;
import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors.Palette;
import generic.theme.Gui;
import ghidra.graph.viewer.vertex.AbstractVisualVertex;
import ghidra.graph.viewer.vertex.VertexShapeProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.StringUtilities;
import resources.Icons;
import resources.ResourceManager;

// A GraphCutVertex

public class GraphCutVertex extends AbstractVisualVertex implements VertexShapeProvider {

	public static final Color DEFAULT_VERTEX_SHAPE_COLOR = new GColor("color.bg.plugin.fcg.vertex.default");
	private static final Color TOO_BIG_VERTEX_SHAPE_COLOR = new GColor("color.bg.plugin.fcg.vertex.toobig");
	
	//@formatter:on
	
	public static final Icon NOT_ALLOWED_ICON = Icons.ERROR_ICON;
	private static final Icon EXPAND_ICON =
		ResourceManager.getScaledIcon(Icons.EXPAND_ALL_ICON, 10, 10);
	private static final Icon COLLAPSE_ICON =
		ResourceManager.getScaledIcon(Icons.COLLAPSE_ALL_ICON, 10, 10);

	// higher numbered layers go on top
	private static final Integer VERTEX_SHAPE_LAYER = 100;
	private static final Integer TOGGLE_BUTTON_LAYER = 200;
	private static final Integer LABEL_LAYER = 300;

	private static final int GAP = 2;
	private static final int VERTEX_SHAPE_SIZE = 50;

	private static final int MAX_NAME_LENGTH = 30;
	
	private Namespace namespace;
	
	private JLayeredPane layeredPane;
	private JButton toggleInsButton = new EmptyBorderButton(EXPAND_ICON);
	private JButton toggleOutsButton = new EmptyBorderButton(EXPAND_ICON);
	private JLabel nameLabel = new GDLabel();
	private JLabel vertexImageLabel = new GDLabel();

	private Double vertexShape;
	private Double compactShape;
	private Shape fullShape;

	// these values are set after construction from external sources
	private boolean hasIncomingReferences;
	private boolean hasOutgoingReferences;
	private boolean tooManyIncomingReferences;
	private boolean tooManyOutgoingReferences;
	private boolean incomingExpanded;
	private boolean outgoingExpanded;

	// set this to true to see borders around the components of this vertex
	private boolean useDebugBorders = false;

	private Paint inPaint;
	private Paint outPaint;

	private GraphCutLevel level;
	
	// Dynamic Layout Variables
	public int layoutIndex;
	public boolean visible;
	
	/**
	 * Constructor
	 * @param namespace Namespace represented by this vertex
	 * @param level The level of this vertex
	 * @param expansionListener listener for expanding connections to this vertex
	 */
	public GraphCutVertex(Namespace namespace, GraphCutLevel level, GraphCutExpansionListener expansionListener) {
		this.namespace = namespace;
		this.level = level;
		Objects.requireNonNull(expansionListener);
		
		toggleInsButton.addActionListener(e -> {
			if (tooManyIncomingReferences) {
				return;
			}
			expansionListener.toggleIncomingVertices(GraphCutVertex.this);
		});

		toggleOutsButton.addActionListener(e -> {
			if (tooManyOutgoingReferences) {
				return;
			}
			expansionListener.toggleOutgoingVertices(GraphCutVertex.this);
		});

		buildUi();

		setTogglesVisible(false);
	}
	
	private void createPaints() {
		
		Color vertexShapeColor = getVertexShapeColor();

		Color lightColor = vertexShapeColor;
		Color darkColor = Gui.darker(vertexShapeColor);
		Color darkestColor = Gui.darker(darkColor);
		
		int offset = 5 * level.getDistance();
		int half = VERTEX_SHAPE_SIZE / 2;
		int start = 0;
		int end = half + offset;

		// paint top-down: dark to light for incoming; light to dark for outgoing
		inPaint = new LinearGradientPaint(new Point(0, start), new Point(0, end),
			new float[] { .0f, .2f, 1f }, new Color[] { darkestColor, darkColor, lightColor });

		start = half - offset; // (offset + 10);
		end = VERTEX_SHAPE_SIZE;
		outPaint = new LinearGradientPaint(new Point(0, start), new Point(0, end),
			new float[] { .0f, .8f, 1f }, new Color[] { lightColor, darkColor, darkestColor });
		
	}
	
	private void buildUi() {
		
		createPaints();
		
		String truncated = StringUtilities.trimMiddle(getName(), MAX_NAME_LENGTH);
		nameLabel.setText(truncated);
		buildVertexShape();
		
		// calculate the needed size
		layeredPane = new JLayeredPane();
		Border border = createDebugBorder(new LineBorder(Palette.GOLD, 1));
		layeredPane.setBorder(border);

		updateLayeredPaneSize();

		// layout the components
		addVertexShape();
		addToggleButtons();
		addNameLabel();

		buildFullShape();
	}
	
	private Border createDebugBorder(Border border) {
		if (useDebugBorders) {
			return border;
		}
		return BorderFactory.createEmptyBorder();
	}

	private void buildFullShape() {

		// Note: this method assumes all bounds have been set
		Area parent = new Area();

		Area v = new Area(vertexShape);
		Area name = new Area(nameLabel.getBounds());
		parent.add(v);
		parent.add(name);

		// for now, the buttons only appear on hover, but if we want to avoid clipping when
		// painting, we need to account for them in the shape's overall bounds
		Area in = new Area(toggleInsButton.getBounds());
		Area out = new Area(toggleOutsButton.getBounds());
		parent.add(in);
		parent.add(out);

		fullShape = parent;
	}
	
	private void updateLayeredPaneSize() {
		
		//
		// The overall component size is the total width and height of all components, with any
		// spacing between them.
		//

		Dimension shapeSize = vertexImageLabel.getPreferredSize();
		Dimension nameLabelSize = nameLabel.getPreferredSize();
		int height = shapeSize.height + GAP + nameLabelSize.height;

		Dimension insSize = toggleInsButton.getPreferredSize();
		Dimension outsSize = toggleOutsButton.getPreferredSize();
		int buttonWidth = Math.max(insSize.width, outsSize.width);
		int offset = buttonWidth / 3; // overlap the vertex shape

		int width = offset + shapeSize.width;
		width = Math.max(width, nameLabelSize.width);

		layeredPane.setPreferredSize(new Dimension(width, height));
	}
	
	private void buildVertexShape() {
		int w = VERTEX_SHAPE_SIZE;
		int h = VERTEX_SHAPE_SIZE;
		Double circle = new Ellipse2D.Double(0, 0, w, h);

		BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g2 = (Graphics2D) image.getGraphics();
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		FcgDirection direction = level.getDirection();
		if (direction.isSource()) {
			g2.setColor(getVertexShapeColor());
		}
		else if (direction.isIn()) {
			g2.setPaint(inPaint);
		}
		else {
			g2.setPaint(outPaint);
		}

		g2.fill(circle);

		g2.dispose();

		vertexShape = circle;
		compactShape = (Double) vertexShape.clone();
		vertexImageLabel.setIcon(new ImageIcon(image));
		
		Border border = createDebugBorder(new LineBorder(Palette.PINK, 1));
		vertexImageLabel.setBorder(border);
	}
	
	private Color getVertexShapeColor() {

		if (isInDirection() && tooManyIncomingReferences) {
			return TOO_BIG_VERTEX_SHAPE_COLOR;
		}

		if (isOutDirection() && tooManyOutgoingReferences) {
			return TOO_BIG_VERTEX_SHAPE_COLOR;
		}

		return DEFAULT_VERTEX_SHAPE_COLOR;
	}

	private boolean isInDirection() {
		FcgDirection direction = level.getDirection();
		boolean isIn = direction.isIn() || direction.isSource();
		return isIn;
	}

	private boolean isOutDirection() {
		FcgDirection direction = level.getDirection();
		boolean isOut = direction.isOut() || direction.isSource();
		return isOut;
	}

	private void addVertexShape() {

		Dimension parentSize = layeredPane.getPreferredSize();
		Dimension size = vertexImageLabel.getPreferredSize();

		// centered
		int x = (parentSize.width / 2) - (size.width / 2);
		int y = 0;

		vertexImageLabel.setBounds(x, y, size.width, size.height);
		Dimension shapeSize = vertexShape.getBounds().getSize();

		// setFrame() will make sure the shape's x,y values are where they need to be
		// for the later 'full shape' creation
		vertexShape.setFrame(x, y, shapeSize.width, shapeSize.height);
		layeredPane.add(vertexImageLabel, VERTEX_SHAPE_LAYER);
	}
	
	private void addNameLabel() {
		Border border = createDebugBorder(new LineBorder(Palette.GREEN, 1));
		nameLabel.setBorder(border);
		
		Rectangle parentBounds = vertexImageLabel.getBounds();
		Dimension size = nameLabel.getPreferredSize();
		
		int x = (parentBounds.x + (parentBounds.width / 2)) - (size.width / 2);
		int y = parentBounds.y + parentBounds.height + GAP;
		nameLabel.setBounds(x, y, size.width, size.height);
		layeredPane.add(nameLabel, LABEL_LAYER);
		
	}
	
	private void addToggleButtons() {

		// hide the button background
		toggleInsButton.setBackground(Palette.NO_COLOR);
		toggleOutsButton.setBackground(Palette.NO_COLOR);

		// This is needed for Flat Dark theme to work correctly, due to the fact that it wants to
		// paint its parent background when the button is opaque.  The parent background will get
		// painted over any items that lie between the button and the parent.
		toggleInsButton.setOpaque(false);
		toggleOutsButton.setOpaque(false);

		Rectangle parentBounds = vertexImageLabel.getBounds();
		Dimension size = toggleInsButton.getPreferredSize();

		// upper toggle; upper-left
		int x = parentBounds.x - (size.width / 3);
		int y = 0;
		toggleInsButton.setBounds(x, y, size.width, size.height);
		layeredPane.add(toggleInsButton, TOGGLE_BUTTON_LAYER);

		// lower toggle; lower-left, lined-up with the vertex shape
		size = toggleOutsButton.getPreferredSize();
		Dimension vertexSize = parentBounds.getSize();
		y = vertexSize.height - size.height;
		toggleOutsButton.setBounds(x, y, size.width, size.height);
		layeredPane.add(toggleOutsButton, TOGGLE_BUTTON_LAYER);
	}

	public String getName() {
		return namespace.getName();
	}
	
	public Namespace getNamespace() {
		return namespace;
	}
	
	public GraphCutLevel getLevel() {
		return level;
	}
	
	public int getDegree() {
		return level.getRow();
	}
	
	public FcgDirection getDirection() {
		return level.getDirection();
	}
	
	public JButton getIncomingToggleButton() {
		return toggleInsButton;
	}
	
	public JButton getOutgoingToggleButton() {
		return toggleOutsButton;
	}
	
	public void setIncomingExpanded(boolean setExpanded) {
		validateIncomingExpandedState(setExpanded);
		
		this.incomingExpanded = setExpanded;
		toggleInsButton.setIcon(setExpanded ? COLLAPSE_ICON : EXPAND_ICON);
		String hideShow = setExpanded ? "hide" : "show";
		toggleInsButton.setToolTipText("Click to " + hideShow + " incoming edges");
	}
	
	private void validateOutgoingExpandedState(boolean isExpanding) {
		if (isExpanding) {
			if (!canExpandOutgoingReferences()) {
				throw new IllegalStateException("Vertex cannot be expanded: " + this);
			}
			return;
		}
		// collapsing
		if (!isOutgoingExpanded()) {
			throw new IllegalStateException("Vertex cannot be collapsed: " + this);
		}
	}
	
	private void validateIncomingExpandedState(boolean expanding) {

		if (expanding) {
			if (!canExpandIncomingReferences()) {
				throw new IllegalStateException("Vertex cannot be expanded: " + this);
			}
			return;
		}

		// collapsing
		if (!isIncomingExpanded()) {
			throw new IllegalStateException("Vertex cannot be collapsed: " + this);
		}
	}
	
	/**
	 * Returns true if this vertex is showing all edges in the incoming direction
	 *
	 * @return true if this vertex is showing all edges in the incoming direction
	 */
	public boolean isIncomingExpanded() {
		return incomingExpanded;
	}

	/**
	 * Sets to true if this vertex is showing all edges in the outgoing direction
	 *
	 * @param setExpanded true if this vertex is showing all edges in the outgoing direction
	 */
	public void setOutgoingExpanded(boolean setExpanded) {

		validateOutgoingExpandedState(setExpanded);

		this.outgoingExpanded = setExpanded;
		toggleOutsButton.setIcon(setExpanded ? COLLAPSE_ICON : EXPAND_ICON);
		String hideShow = setExpanded ? "hide" : "show";
		toggleInsButton.setToolTipText("Click to " + hideShow + " outgoing edges");
	}

	
	/**
	 * Returns true if this vertex is showing all edges in the outgoing direction
	 *
	 * @return true if this vertex is showing all edges in the outgoing direction
	 */
	public boolean isOutgoingExpanded() {
		return outgoingExpanded;
	}
	
	/**
	 * Returns whether this vertex is fully expanded in its current direction
	 *
	 * @return whether this vertex is fully expanded in its current direction
	 */
	public boolean isExpanded() {
		FcgDirection direction = level.getDirection();
		if (direction.isSource()) {
			return isIncomingExpanded() && isOutgoingExpanded();
		}
		if (direction.isIn()) {
			return isIncomingExpanded();
		}
		return isOutgoingExpanded();
	}
	
	/**
	 * Sets whether this vertex has too many incoming references, where too many is subjectively
	 * defined by this class.  Too many nodes in the display would ruin rendering and general
	 * usability.
	 *
	 * @param tooMany if there are too many references
	 */
	public void setTooManyIncomingReferences(boolean tooMany) {
		this.tooManyIncomingReferences = tooMany;
		toggleInsButton.setIcon(NOT_ALLOWED_ICON);
		toggleInsButton.setToolTipText("Too many incoming references to show");
		buildUi();
	}

	/**
	 * Sets whether this vertex has too many outgoing references, where too many is subjectively
	 * defined by this class.  Too many nodes in the display would ruin rendering and general
	 * usability.
	 *
	 * @param tooMany if there are too many references
	 */
	public void setTooManyOutgoingReferences(boolean tooMany) {
		this.tooManyOutgoingReferences = tooMany;
		toggleOutsButton.setIcon(NOT_ALLOWED_ICON);
		toggleOutsButton.setToolTipText("Too many outgoing references to show");
		buildUi();
	}

	/**
	 * Returns whether this vertex has too many incoming references, where too many is subjectively
	 * defined by this class.  Too many nodes in the display would ruin rendering and general
	 * usability.
	 *
	 * @return true if there are too many references
	 */
	public boolean hasTooManyIncomingReferences() {
		return tooManyIncomingReferences;
	}

	/**
	 * Returns whether this vertex has too many outgoing references, where too many is subjectively
	 * defined by this class.  Too many nodes in the display would ruin rendering and general
	 * usability.
	 *
	 * @return true if there are too many references
	 */
	public boolean hasTooManyOutgoingReferences() {
		return tooManyOutgoingReferences;
	}

	/**
	 * Returns true if this vertex can expand itself in its current direction, or in either
	 * direction if this is a source vertex
	 *
	 * @return true if this vertex can be expanded
	 */
	public boolean canExpand() {
		FcgDirection direction = level.getDirection();
		if (direction.isSource()) {
			return canExpandIncomingReferences() || canExpandOutgoingReferences();
		}

		if (direction.isIn()) {
			return canExpandIncomingReferences();
		}

		return canExpandOutgoingReferences();
	}
	

	public boolean canExpandIncomingReferences() {
		return hasIncomingReferences && !tooManyIncomingReferences && !incomingExpanded;
	}

	public boolean canExpandOutgoingReferences() {
		return hasOutgoingReferences && !tooManyOutgoingReferences && !outgoingExpanded;
	}

	/**
	 * Sets whether this vertex has any incoming references
	 *
	 * @param hasIncoming true if this vertex has any incoming references
	 */
	public void setHasIncomingReferences(boolean hasIncoming) {
		this.hasIncomingReferences = hasIncoming;
	}

	/**
	 * Sets whether this vertex has any outgoing references
	 *
	 * @param hasOutgoing true if this vertex has any outgoing references
	 */

	public void setHasOutgoingReferences(boolean hasOutgoing) {
		this.hasOutgoingReferences = hasOutgoing;
	}

	@Override
	public void setHovered(boolean hovered) {
		super.setHovered(hovered);

		setTogglesVisible(hovered);
	}

	private void setTogglesVisible(boolean visible) {

		boolean isIn = isInDirection();
		boolean turnOn = isIn && hasIncomingReferences && visible;
		toggleInsButton.setVisible(turnOn);

		boolean isOut = isOutDirection();
		turnOn = isOut && hasOutgoingReferences && visible;
		toggleOutsButton.setVisible(turnOn);
	}

	
	@Override
	public JComponent getComponent() {
		return layeredPane;
	}

	@Override
	public Shape getCompactShape() {
		return compactShape;
	}

	@Override
	public Shape getFullShape() {
		return fullShape;
	}

	@Override
	public String toString() {
		return getName();// + " @ " + level; // + " (" + System.identityHashCode(this) + ')';
	}

	@Override
	public int hashCode() {
		return Objects.hash(namespace);
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		
		if(getClass() != obj.getClass()) {
			return false;
		}
		
		GraphCutVertex other = (GraphCutVertex) obj;
		return Objects.equals(namespace, other.namespace);
	}
	
	@Override
	public void dispose() {
		// nothing to do
	}
	
	public long getID() {
		return getNamespace().getID();
	}

}
















