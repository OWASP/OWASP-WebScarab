<xsl:stylesheet xmlns:xsl = "http://www.w3.org/1999/XSL/Transform" version = "1.0" >

<xsl:template match="workproduct">
	<html>
	<head>
	<title><xsl:value-of select="@project" />: <xsl:value-of select="@identifier" /></title>
	</head>
	<body bgcolor="#FFFFFF" >
	<h2><xsl:value-of select="@stage" />: <xsl:value-of select="@identifier" /></h2>
	
	<xsl:apply-templates />
	</body></html>
</xsl:template>

<xsl:template match="header">
	<table border="0" width="100%" cellspacing="0" cellpadding="1" bgcolor="#000000"><tr><td>
		<table cellspacing="0" cellpadding="3" border="0" width="100%" bgcolor="#FFFFFF"><tr>
		<xsl:apply-templates />
		</tr></table>
	</td>
	</tr></table>
</xsl:template>

<xsl:template match="date">
	<td><b><xsl:apply-templates /></b></td>
</xsl:template>

<xsl:template match="owner">
	<td><b>Owner: </b><xsl:text>  </xsl:text><xsl:apply-templates /></td>
</xsl:template>


<xsl:template match="author">
	<td><b><xsl:apply-templates /></b></td>
</xsl:template>


<xsl:template match="status">
	<td><b>Status:</b><xsl:text>  </xsl:text><xsl:value-of select="@value" /></td>
</xsl:template>


<xsl:template match="issues">
	<p></p>

	<table border="0" width="100%" cellspacing="0" cellpadding="1" bgcolor="#000000"><tr><td>
		
		<table cellspacing="0" cellpadding="3" border="0" width="100%" bgcolor="#FFFFFF">
		<tr><td><h3>Issues</h3></td></tr>
		<tr><td>
		<ul>
		<xsl:apply-templates />
		</ul>
		</td>
		</tr></table>
	</td>
	</tr></table>


</xsl:template>

<xsl:template match="metrics">
	<p></p>

	<table border="0" width="100%" cellspacing="0" cellpadding="1" bgcolor="#000000"><tr><td>
		
		<table border="0" cellspacing="0" cellpadding="3" width="100%" bgcolor="#FFFFFF">
		<tr><td><h3>Metrics</h3></td></tr>
		<tr><td>
		<ul>
		<xsl:apply-templates />
		</ul>
		</td>
		</tr></table>
	</td>
	</tr></table>

</xsl:template>

<xsl:template match="traceability">
	<p></p>

	<table border="0" width="100%" cellspacing="0" cellpadding="1" bgcolor="#000000"><tr><td>
		<table border="0" cellspacing="0" cellpadding="3" width="100%" bgcolor="#FFFFFF">
		<tr><td><h3>Traceability</h3></td></tr>
		<tr><td>
		<p>Impacted By:</p>
		<ul>
			<xsl:apply-templates select="impacted-by"/>
		</ul>
	
		<p>Impacts:</p>
		<ul>
			<xsl:apply-templates select="impacts" />
		</ul>
		</td></tr>
		</table>
		</td>
		</tr></table>
</xsl:template>


<xsl:template match="impacted-by">
	<li><a href="../{@stage}/{@identifier}.html"><xsl:value-of select="@stage" />/<xsl:value-of select="@identifier" /></a></li>
</xsl:template>

<xsl:template match="impacts">
	<li><a href="../{@stage}/{@identifier}.html"><xsl:value-of select="@stage" />/<xsl:value-of select="@identifier" /></a></li>
</xsl:template>


<xsl:template match="history">
	<p></p>

	<table border="0" width="100%" cellspacing="0" cellpadding="1" bgcolor="#000000"><tr><td>
		
		<table cellspacing="0" cellpadding="3" border="0" width="100%" bgcolor="#FFFFFF">
		<tr><td><h3>History</h3></td></tr>
		<tr><td>
		<pre>
		<xsl:apply-templates />
		</pre>
		</td>
		</tr></table>
	</td>
	</tr></table>

</xsl:template>

<xsl:template match="details">
	<p></p>

	<table border="0" width="100%" cellspacing="0" cellpadding="1" bgcolor="#000000"><tr><td>
		
		<table cellspacing="0" cellpadding="3"  border="0" width="100%" bgcolor="#FFFFFF">
		<tr><td><h3>Details</h3></td></tr>
		<tr><td>
			<xsl:copy-of select="*" />	
		</td>
		</tr></table>
	</td>
	</tr></table>

</xsl:template>

<xsl:template match="item">
	<li><xsl:apply-templates /></li>
</xsl:template>

<xsl:template match="entry">
    <li><xsl:value-of select="@date"/>: <xsl:apply-templates /></li>
</xsl:template>


<!-- creates the workbook index file -->
<xsl:template match="workbook">
<html>
<body>
	<xsl:apply-templates select="phase" />	
</body>
</html>
</xsl:template>

<xsl:template match="phase">
	<h1>
		<xsl:value-of select="name"/>
	</h1>
	<ul>
		<xsl:apply-templates select="workproduct" />
	</ul>
</xsl:template>

<xsl:template match="name">
	<xsl:apply-templates/>
</xsl:template>

<xsl:template match="phase/workproduct">
	<li>
	<xsl:element name="a">
	<xsl:attribute name="href">
	<xsl:value-of select="ancestor::phase/name" />/<xsl:value-of select="name" />.html</xsl:attribute>
	<xsl:attribute name="target">product</xsl:attribute>
	<xsl:value-of select="name" />
	</xsl:element>
	</li>
</xsl:template>


<!-- creates the index.html page with the frameset -->
<xsl:template match="frameset">
	<html>
	<head>
		<title>
			<xsl:apply-templates select="title" />
		</title>
		</head>
	<FRAMESET cols="250,*" >
    <FRAME NAME="workbook" SRC="workbook.html" SCROLLING="auto" >
		</FRAME>
    <FRAME name="product" src="Requirements/Problem_Statement.html" scrolling="auto">
		</FRAME>
  </FRAMESET>
 </html>
</xsl:template>

</xsl:stylesheet>
